#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/mobility-module.h"
#include "ns3/internet-module.h"
#include "ns3/aodv-module.h"
#include "ns3/wifi-module.h"
#include "ns3/applications-module.h"
#include "ns3/netanim-module.h"
#include "ns3/random-variable-stream.h"
#include <iomanip>
#include <iostream>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("FloodingAttackSimulation");

// Global counters for legitimate traffic
uint32_t g_packetsSent = 0;
uint32_t g_packetsReceived = 0;
uint32_t g_floodingPacketsSent = 0;

// Trace callbacks
void TxCallback(Ptr<const Packet>) { g_packetsSent++; }
void RxCallback(Ptr<const Packet>) { g_packetsReceived++; }

// FlooderApplication: burst flooding without defense
class FlooderApplication : public Application
{
public:
  FlooderApplication() : m_socket(nullptr) {}
  virtual ~FlooderApplication() {}

  void Setup(double interval, uint32_t packetSize)
  {
    m_interval = interval;
    m_packetSize = packetSize;
  }

private:
  virtual void StartApplication() override
  {
    NS_LOG_INFO("FlooderApplication starting on node " << GetNode()->GetId());
    m_socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
    m_socket->Bind();
    m_socket->SetAllowBroadcast(true);
    ScheduleSend();
  }

  virtual void StopApplication() override
  {
    NS_LOG_INFO("FlooderApplication stopping. Sent " << g_floodingPacketsSent << " packets");
    if (m_socket) {
      m_socket->Close();
      m_socket = nullptr;
    }
    if (m_event.IsRunning()) {
      Simulator::Cancel(m_event);
    }
  }

  void ScheduleSend()
  {
    m_event = Simulator::Schedule(Seconds(m_interval), &FlooderApplication::Send, this);
  }

  void Send()
  {
    // Burst of 3 packets each interval
    Ptr<UniformRandomVariable> rnd = CreateObject<UniformRandomVariable>();
    for (int i = 0; i < 3; ++i) {
      uint32_t randIp = rnd->GetValue(1, 0xfffffffe);
      Ipv4Address dest(randIp);
      Ptr<Packet> pkt = Create<Packet>(m_packetSize);
      m_socket->SendTo(pkt, 0, InetSocketAddress(dest, 9));
      g_floodingPacketsSent++;
      NS_LOG_INFO("Flooder sent packet " << g_floodingPacketsSent << " to " << dest);
    }
    ScheduleSend();
  }

  Ptr<Socket> m_socket;
  EventId m_event;
  double m_interval{0.005};  // 200 bursts/sec => 600 pkt/s
  uint32_t m_packetSize{512};
};

int main(int argc, char *argv[])
{
  uint32_t numNodes = 15;      // total nodes (last is attacker)
  double simTime = 30.0;
  bool enablePcap = true;

  CommandLine cmd;
  cmd.AddValue("enablePcap", "Enable PCAP tracing", enablePcap);
  cmd.Parse(argc, argv);

  LogComponentEnable("FloodingAttackSimulation", LOG_LEVEL_INFO);

  // Create nodes
  NodeContainer nodes;
  nodes.Create(numNodes);
  Ptr<Node> attacker = nodes.Get(numNodes - 1);

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

  // Mobility: moderate speed
  MobilityHelper mobility;
  mobility.SetPositionAllocator("ns3::GridPositionAllocator",
    "MinX", DoubleValue(-100.0), "MinY", DoubleValue(-100.0),
    "DeltaX", DoubleValue(50.0),  "DeltaY", DoubleValue(50.0),
    "GridWidth", UintegerValue(4), "LayoutType", StringValue("RowFirst"));
  mobility.SetMobilityModel("ns3::RandomWalk2dMobilityModel",
    "Bounds", RectangleValue(Rectangle(-150, 150, -150, 150)),
    "Speed", StringValue("ns3::UniformRandomVariable[Min=1.0|Max=3.0]"));
  mobility.Install(nodes);

  // Install AODV on normal nodes
  AodvHelper aodv;
  InternetStackHelper stack;
  stack.SetRoutingHelper(aodv);
  stack.Install(nodes);

  // Assign IPs
  Ipv4AddressHelper addr;
  addr.SetBase("10.0.0.0", "255.255.255.0");
  Ipv4InterfaceContainer ifs = addr.Assign(devices);

  // Legitimate UDP traffic: server on node numNodes-2, client on node 0
  uint32_t serverId = numNodes - 2;
  UdpServerHelper server(9);
  ApplicationContainer serverApps = server.Install(nodes.Get(serverId));
  serverApps.Start(Seconds(1.0));
  serverApps.Stop(Seconds(simTime));

  UdpClientHelper client(ifs.GetAddress(serverId), 9);
  client.SetAttribute("MaxPackets", UintegerValue(1000));
  client.SetAttribute("Interval", TimeValue(Seconds(0.1)));
  client.SetAttribute("PacketSize", UintegerValue(512));
  ApplicationContainer clientApps = client.Install(nodes.Get(0));
  clientApps.Start(Seconds(2.0));
  clientApps.Stop(Seconds(simTime));

  // Install flooding attack application on attacker node
  Ptr<FlooderApplication> floodApp = CreateObject<FlooderApplication>();
  floodApp->Setup(0.005, 512);  // 600 pkt/s
  attacker->AddApplication(floodApp);
  floodApp->SetStartTime(Seconds(5.0));
  floodApp->SetStopTime(Seconds(simTime - 1.0));

  // Trace legitimate traffic
  clientApps.Get(0)->TraceConnectWithoutContext("Tx", MakeCallback(&TxCallback));
  serverApps.Get(0)->TraceConnectWithoutContext("Rx", MakeCallback(&RxCallback));

  // Enable PCAP
  if (enablePcap) {
    phy.EnablePcapAll("flooding-attack");
    std::cout << "PCAP enabled for flood analysis" << std::endl;
  }

  // NetAnim visualization
  AnimationInterface anim("flooding-attack.xml");
  for (uint32_t i = 0; i < numNodes - 1; ++i) {
    anim.UpdateNodeColor(nodes.Get(i), 0, 255, 0);  // green normal
  }
  anim.UpdateNodeColor(attacker, 255, 0, 0);        // red attacker

  // Run simulation
  Simulator::Stop(Seconds(simTime));
  Simulator::Run();
  Simulator::Destroy();

  // Output results
  double pdr = (g_packetsSent > 0) ? 100.0 * g_packetsReceived / g_packetsSent : 0.0;
  double attackRate = g_floodingPacketsSent / simTime;

  std::cout << "\n===== RREQ Flooding Attack Simulation Results =====\n";
  std::cout << "Legitimate Packets Sent:     " << g_packetsSent << "\n";
  std::cout << "Legitimate Packets Received: " << g_packetsReceived << "\n";
  std::cout << "PDR (%):                     " << std::fixed << std::setprecision(2) << pdr << "\n";
  std::cout << "Flooding Packets Sent:       " << g_floodingPacketsSent << "\n";
  std::cout << "Attack Rate (pkt/sec):       " << std::fixed << std::setprecision(2) << attackRate << "\n";
  std::cout << "======================================\n";

  return 0;
}

