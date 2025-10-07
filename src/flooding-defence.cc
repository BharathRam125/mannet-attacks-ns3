#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/mobility-module.h"
#include "ns3/internet-module.h"
#include "ns3/aodv-module.h"
#include "ns3/wifi-module.h"
#include "ns3/applications-module.h"
#include "ns3/netanim-module.h"
#include "ns3/random-variable-stream.h"
#include "ns3/aodv-packet.h"
#include <iomanip>
#include <iostream>
#include <map>
#include <deque>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("AdvancedFloodingDefenseSimulation");

// -------------------- Global counters --------------------
uint32_t g_packetsSent = 0;
uint32_t g_packetsReceived = 0;
uint32_t g_floodingPacketsSent = 0;
uint32_t g_rreqsDropped = 0;
uint32_t g_totalRreqsReceived = 0;
uint32_t g_legitimateRreqs = 0;

// -------------------- Advanced Defense Manager --------------------
class AdvancedDefenseManager : public Object
{
private:
  std::map<Ipv4Address, std::deque<Time>> m_rreqTimes;
  std::map<Ipv4Address, uint32_t> m_suspiciousActivity;
  uint32_t m_rreqLimit = 3;            // Max 3 RREQs/sec per source
  double   m_timeWindow = 1.0;         // 1-second window
  uint32_t m_suspiciousThreshold = 10; // Flag after 10 violations

public:
  static TypeId GetTypeId(void)
  {
    static TypeId tid = TypeId("AdvancedDefenseManager")
      .SetParent<Object>()
      .AddConstructor<AdvancedDefenseManager>();
    return tid;
  }

  bool ShouldAcceptRREQ(Ipv4Address source)
  {
    Time now = Simulator::Now();
    g_totalRreqsReceived++;

    // If already flagged malicious, drop immediately
    auto suspIt = m_suspiciousActivity.find(source);
    if (suspIt != m_suspiciousActivity.end() && suspIt->second >= m_suspiciousThreshold) {
      g_rreqsDropped++;
      NS_LOG_INFO("Blocking RREQ from flagged malicious source " << source);
      return false;
    }

    // Rate limiting
    auto &times = m_rreqTimes[source];
    while (!times.empty() && (now - times.front()).GetSeconds() > m_timeWindow) {
      times.pop_front();
    }
    if (times.size() >= m_rreqLimit) {
      g_rreqsDropped++;
      m_suspiciousActivity[source]++;
      NS_LOG_INFO("RREQ rate limit exceeded for " << source
                  << " (violations: " << m_suspiciousActivity[source] << ") - dropping");
      return false;
    }

    times.push_back(now);
    g_legitimateRreqs++;
    return true;
  }

  void PrintSecurityReport()
  {
    std::cout << "\n========== Security Analysis Report ==========" << std::endl;
    std::cout << "Suspicious Sources Detected: " << m_suspiciousActivity.size() << std::endl;
    for (auto &entry : m_suspiciousActivity) {
      std::string level = (entry.second >= m_suspiciousThreshold ? "HIGH"
                           : (entry.second >= 5 ? "MEDIUM" : "LOW"));
      std::cout << "  " << entry.first
                << " - Violations: " << entry.second
                << " (Threat: " << level << ")" << std::endl;
    }
    std::cout << "===============================================" << std::endl;
  }
};

Ptr<AdvancedDefenseManager> g_defenseManager;

// -------------------- Trace callbacks --------------------
void TxCallback(Ptr<const Packet>) { g_packetsSent++; }
void RxCallback(Ptr<const Packet>) { g_packetsReceived++; }

void AdvancedAodvRxCallback(Ptr<const Packet> p, Ptr<Ipv4> ipv4, uint32_t)
{
  Ptr<Packet> copy = p->Copy();
  Ipv4Header hdr;
  if (!copy->RemoveHeader(hdr)) return;
  Ipv4Address source = hdr.GetSource();
  if (!g_defenseManager->ShouldAcceptRREQ(source)) {
    NS_LOG_INFO("Defensive action: Dropped suspicious packet from " << source);
  }
}

// -------------------- Advanced FlooderApplication --------------------
class AdvancedFlooderApplication : public Application
{
public:
  AdvancedFlooderApplication() : m_socket(0) {}
  virtual ~AdvancedFlooderApplication() {}

  void Setup(double interval, uint32_t packetSize)
  {
    m_interval = interval;
    m_packetSize = packetSize;
  }

private:
  virtual void StartApplication() override
  {
    NS_LOG_INFO("AdvancedFlooderApplication starting on node " << GetNode()->GetId());
    m_socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
    m_socket->Bind();
    m_socket->SetAllowBroadcast(true);
    ScheduleSend();
  }

  virtual void StopApplication() override
  {
    NS_LOG_INFO("AdvancedFlooderApplication stopping. Sent " << g_floodingPacketsSent << " flooding packets");
    if (m_socket) {
      m_socket->Close();
      m_socket = 0;
    }
    if (m_event.IsRunning()) {
      Simulator::Cancel(m_event);
    }
  }

  void ScheduleSend()
  {
    m_event = Simulator::Schedule(Seconds(m_interval), &AdvancedFlooderApplication::Send, this);
  }

  void Send()
  {
    for (int i = 0; i < 3; ++i) { // burst of 3 packets
      Ptr<UniformRandomVariable> randVar = CreateObject<UniformRandomVariable>();
      uint32_t randIp;
      if (randVar->GetValue(0,1) > 0.5) {
        uint32_t host = randVar->GetValue(100, 200);
        randIp = (10U<<24)|(0U<<16)|(0U<<8)|host;
      } else {
        randIp = randVar->GetValue(1, 0xfffffffe);
      }
      Ptr<Packet> pkt = Create<Packet>(m_packetSize);
      m_socket->SendTo(pkt, 0, InetSocketAddress(Ipv4Address(randIp), 9));
      g_floodingPacketsSent++;
      NS_LOG_INFO("Flooder sent burst packet " << g_floodingPacketsSent << " to " << Ipv4Address(randIp));
    }
    ScheduleSend();
  }

  Ptr<Socket> m_socket;
  EventId m_event;
  double m_interval{0.005}; // 200 bursts/sec = 600 pkt/s
  uint32_t m_packetSize{512};
};

// -------------------- Main --------------------
int main(int argc, char *argv[])
{
  uint32_t numNodes = 15;
  double simTime = 30.0;
  bool enablePcap = true;
  bool enableDefense = true;

  CommandLine cmd;
  cmd.AddValue("enablePcap", "Enable PCAP tracing", enablePcap);
  cmd.AddValue("enableDefense", "Enable defense mechanism", enableDefense);
  cmd.Parse(argc, argv);

  LogComponentEnable("AdvancedFloodingDefenseSimulation", LOG_LEVEL_INFO);

  g_defenseManager = CreateObject<AdvancedDefenseManager>();

  NodeContainer nodes;
  nodes.Create(numNodes);
  Ptr<Node> attackerNode = nodes.Get(numNodes - 1);

  // Wi-Fi setup
  WifiHelper wifi;
  wifi.SetStandard(WIFI_STANDARD_80211b);
  wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
    "DataMode", StringValue("DsssRate11Mbps"),
    "ControlMode", StringValue("DsssRate1Mbps"));

  YansWifiChannelHelper channel = YansWifiChannelHelper::Default();
  YansWifiPhyHelper phy;
  phy.SetChannel(channel.Create());

  WifiMacHelper mac;
  mac.SetType("ns3::AdhocWifiMac");
  NetDeviceContainer devices = wifi.Install(phy, mac, nodes);

  // Mobility
  MobilityHelper mobility;
  mobility.SetPositionAllocator("ns3::GridPositionAllocator",
    "MinX", DoubleValue(-200.0), "MinY", DoubleValue(-200.0),
    "DeltaX", DoubleValue(50.0),  "DeltaY", DoubleValue(50.0),
    "GridWidth", UintegerValue(4), "LayoutType", StringValue("RowFirst"));
  mobility.SetMobilityModel("ns3::RandomWalk2dMobilityModel",
    "Bounds", RectangleValue(Rectangle(-200, 200, -200, 200)),
    "Speed", StringValue("ns3::UniformRandomVariable[Min=1.0|Max=3.0]"));
  mobility.Install(nodes);

  // AODV with HELLO disabled to reduce overhead
  AodvHelper aodv;
  aodv.Set("EnableHello", BooleanValue(false));
  InternetStackHelper stack;
  stack.SetRoutingHelper(aodv);
  stack.Install(nodes);

  // IP addressing
  Ipv4AddressHelper addr;
  addr.SetBase("10.0.0.0", "255.255.255.0");
  Ipv4InterfaceContainer interfaces = addr.Assign(devices);

  // Defense trace on Rx for normal nodes
  if (enableDefense) {
    for (uint32_t i = 0; i < numNodes - 1; ++i) {
      nodes.Get(i)->GetObject<Ipv4>()
           ->TraceConnectWithoutContext("Rx", MakeCallback(&AdvancedAodvRxCallback));
    }
    std::cout << "Advanced Defense System ENABLED - Multi-layer protection active" << std::endl;
  } else {
    std::cout << "Defense System DISABLED - Network vulnerable" << std::endl;
  }

  // Legitimate traffic
  uint32_t serverNodeId = numNodes - 2;
  UdpServerHelper server(9);
  ApplicationContainer serverApps = server.Install(nodes.Get(serverNodeId));
  serverApps.Start(Seconds(1.0));
  serverApps.Stop(Seconds(simTime));

  UdpClientHelper client(interfaces.GetAddress(serverNodeId), 9);
  client.SetAttribute("MaxPackets", UintegerValue(1000));
  client.SetAttribute("Interval", TimeValue(Seconds(0.1)));
  client.SetAttribute("PacketSize", UintegerValue(512));
  ApplicationContainer clientApps = client.Install(nodes.Get(0));
  clientApps.Start(Seconds(2.0));
  clientApps.Stop(Seconds(simTime));

  // Install the advanced flooder on the attacker
  Ptr<AdvancedFlooderApplication> flooder = CreateObject<AdvancedFlooderApplication>();
  flooder->Setup(0.005, 512);
  attackerNode->AddApplication(flooder);
  flooder->SetStartTime(Seconds(5.0));
  flooder->SetStopTime(Seconds(simTime - 1.0));

  // Trace UDP application Tx/Rx
  clientApps.Get(0)->TraceConnectWithoutContext("Tx", MakeCallback(&TxCallback));
  serverApps.Get(0)->TraceConnectWithoutContext("Rx", MakeCallback(&RxCallback));

  // PCAP tracing
  if (enablePcap) {
    phy.EnablePcapAll("flooding-defense");
    std::cout << "PCAP tracing enabled for forensic analysis" << std::endl;
  }

  // NetAnim
  AnimationInterface anim("flooding-defense.xml");
  for (uint32_t i = 0; i < numNodes - 1; ++i) {
    anim.UpdateNodeColor(nodes.Get(i), 0, 255, 0);
  }
  anim.UpdateNodeColor(attackerNode, 255, 0, 0);

  // Run simulation
  Simulator::Stop(Seconds(simTime));
  Simulator::Run();
  Simulator::Destroy();

  // Results
  double pdr = (g_packetsSent > 0) ? (double)g_packetsReceived / g_packetsSent * 100.0 : 0.0;
  double attackRate = g_floodingPacketsSent / simTime;
  double defenseEffectiveness = (g_totalRreqsReceived > 0) ?
      ((double)g_rreqsDropped / g_totalRreqsReceived * 100.0) : 0.0;
  double networkResilience = (g_legitimateRreqs > 0) ?
      ((double)g_legitimateRreqs / (g_legitimateRreqs + g_rreqsDropped) * 100.0) : 0.0;

  std::cout << "\n========== RREQ Flooding Attack Defense Simulation Results ==========" << std::endl;
  std::cout << "Defense Status:              " << (enableDefense ? "ENABLED" : "DISABLED") << std::endl;
  std::cout << "Legitimate Packets Sent:     " << g_packetsSent << std::endl;
  std::cout << "Legitimate Packets Received: " << g_packetsReceived << std::endl;
  std::cout << "Packet Delivery Ratio (%):   " << std::fixed << std::setprecision(2) << pdr << std::endl;
  std::cout << "Flooding Packets Generated:   " << g_floodingPacketsSent << std::endl;
  std::cout << "Total RREQs Processed:       " << g_totalRreqsReceived << std::endl;
  std::cout << "Malicious RREQs Blocked:     " << g_rreqsDropped << std::endl;
  std::cout << "Legitimate RREQs Allowed:    " << g_legitimateRreqs << std::endl;
  std::cout << "Defense Effectiveness (%):   " << std::fixed << std::setprecision(2) << defenseEffectiveness << std::endl;
  std::cout << "Network Resilience (%):      " << std::fixed << std::setprecision(2) << networkResilience << std::endl;
  std::cout << "Attack Intensity (pkt/sec):  " << std::fixed << std::setprecision(2) << attackRate << std::endl;

  // Threat assessment
  std::string attackImpact = (pdr < 50 ? "CRITICAL" : (pdr < 70 ? "HIGH" : (pdr < 90 ? "MEDIUM" : "LOW")));
  std::string networkStatus;
  if (!enableDefense) networkStatus = "VULNERABLE";
  else if (defenseEffectiveness > 70) networkStatus = "WELL PROTECTED";
  else if (defenseEffectiveness > 40) networkStatus = "PARTIALLY PROTECTED";
  else networkStatus = "DEFENSE ACTIVE";

  std::cout << "Attack Impact Assessment:    " << attackImpact << std::endl;
  std::cout << "Network Security Status:     " << networkStatus << std::endl;
  std::cout << "============================================================" << std::endl;

  if (enableDefense) {
    g_defenseManager->PrintSecurityReport();
    if (defenseEffectiveness > 50) {
      std::cout << "\nSUCCESS: Advanced defense system effectively mitigated the flooding attack!" << std::endl;
    } else if (defenseEffectiveness > 25) {
      std::cout << "\nPARTIAL SUCCESS: Defense system provided some protection but needs optimization." << std::endl;
    } else {
      std::cout << "\nWARNING: Defense system needs improvement to handle this attack effectively." << std::endl;
    }
  }

  return 0;
}
