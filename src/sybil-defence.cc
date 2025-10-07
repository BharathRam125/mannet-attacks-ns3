#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/wifi-module.h"
#include "ns3/aodv-module.h"
#include "ns3/applications-module.h"
#include "ns3/netanim-module.h"
#include <iostream>
#include <vector>
#include <map>
#include <deque>
#include <set>
#include <iomanip>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("SybilDefenseSimulation");

// Global statistics
uint32_t g_totalLegitSent = 0;
uint32_t g_totalLegitReceived = 0;
uint32_t g_attackPacketsSent = 0;
uint32_t g_attackPacketsDropped = 0;

// Detection parameters
double g_detectionWindowSeconds = 5.0;
uint32_t g_maxAllowedRate = 3;
uint32_t g_burstSizeThreshold = 5;

// Detector class with rate and burst attack detection
class SybilDetector : public Object
{
public:
  bool ShouldAccept(Ipv4Address src)
  {
    Time now = Simulator::Now();
    auto &times = m_packetTimes[src];
    while (!times.empty() && (now - times.front()).GetSeconds() > g_detectionWindowSeconds)
      times.pop_front();

    if (times.size() >= g_maxAllowedRate)
    {
      g_attackPacketsDropped++;
      m_violationCounts[src]++;
      NS_LOG_INFO(now.GetSeconds() << "s: [DEFENSE] Rate limit exceeded by " << src
                   << ", violations: " << m_violationCounts[src]);
      return false;
    }

    times.push_back(now);

    if (times.size() >= g_burstSizeThreshold)
    {
      if ((now - times[times.size() - g_burstSizeThreshold]).GetSeconds() < 0.5)
      {
        g_attackPacketsDropped++;
        m_violationCounts[src]++;
        NS_LOG_INFO(now.GetSeconds() << "s: [DEFENSE] Burst attack detected from " << src
                     << ", violations: " << m_violationCounts[src]);
        return false;
      }
    }

    return true;
  }

  void PrintReport()
  {
    std::cout << "\n===== Sybil Defense Report =====\n";
    for (const auto &kv : m_violationCounts)
    {
      std::cout << "IP " << kv.first << " -> Violations: " << kv.second << "\n";
    }
    std::cout << "Total attack packets dropped: " << g_attackPacketsDropped << "\n";
    std::cout << "================================\n";
  }

private:
  std::map<Ipv4Address, std::deque<Time>> m_packetTimes;
  std::map<Ipv4Address, uint32_t> m_violationCounts;
};

Ptr<SybilDetector> g_detector;

void LogLegitTx(Ptr<const Packet>)
{
  g_totalLegitSent++;
  NS_LOG_INFO(Simulator::Now().GetSeconds() << "s: Legit packet sent, total: " << g_totalLegitSent);
}

void LogLegitRx(Ptr<const Packet>)
{
  g_totalLegitReceived++;
  NS_LOG_INFO(Simulator::Now().GetSeconds() << "s: Legit packet received, total: " << g_totalLegitReceived);
}

void DefenseRxCallback(Ptr<const Packet> p, Ptr<Ipv4> ipv4, uint32_t)
{
  Ipv4Header header;
  if (!p->PeekHeader(header))
    return;

  Ipv4Address src = header.GetSource();

  NS_LOG_INFO(Simulator::Now().GetSeconds() << "s: Packet received from " << src
                                          << " at node " << ipv4->GetObject<Node>()->GetId()
                                          << ", packet size: " << p->GetSize());

  if (!g_detector->ShouldAccept(src))
  {
    NS_LOG_INFO(Simulator::Now().GetSeconds() << "s: [DEFENSE] Dropped packet from " << src
                                              << " at node " << ipv4->GetObject<Node>()->GetId());
    return;
  }
  NS_LOG_INFO(Simulator::Now().GetSeconds() << "s: [DEFENSE] Accepted packet from " << src);
}

class SybilApp : public Application
{
public:
  SybilApp() : m_index(0), m_sendEvent() {}

  void Setup(Ptr<Node> node, uint32_t numSybilIds)
  {
    m_node = node;
    uint16_t baseIp = 200;
    for (uint32_t i = 0; i < numSybilIds; ++i)
    {
      std::ostringstream oss;
      oss << "10.0.0." << baseIp + i;
      Ipv4Address ip(oss.str().c_str());
      m_ips.push_back(ip);
    }
  }

protected:
  virtual void StartApplication() override
  {
    m_socket = Socket::CreateSocket(m_node, UdpSocketFactory::GetTypeId());
    m_socket->SetAllowBroadcast(true);
    m_socket->Bind();
    Simulator::Schedule(Seconds(15.0), &SybilApp::SendBurst, this);
  }

  virtual void StopApplication() override
  {
    if (m_sendEvent.IsRunning())
      Simulator::Cancel(m_sendEvent);
    if (m_socket)
    {
      m_socket->Close();
      m_socket = nullptr;
    }
  }

private:
  void SendBurst()
  {
    if (!m_socket || m_ips.empty())
      return;

    for (int i = 0; i < 6; ++i)
    {
      Ipv4Address src = m_ips[m_index++ % m_ips.size()];
      Ptr<Packet> pkt = Create<Packet>(128);
      InetSocketAddress remote(Ipv4Address("255.255.255.255"), 9);
      int sent = m_socket->SendTo(pkt, 0, remote);
      if (sent >= 0)
      {
        g_attackPacketsSent++;
        NS_LOG_INFO(Simulator::Now().GetSeconds() << "s: Attack burst pkt " << (i + 1)
                                                  << " sent from " << src << ", total sent: " << g_attackPacketsSent);
      }
      else
      {
        NS_LOG_WARN("Failed to send attack pkt from " << src);
      }
    }
    m_sendEvent = Simulator::Schedule(Seconds(0.02), &SybilApp::SendBurst, this);
  }

  Ptr<Node> m_node;
  Ptr<Socket> m_socket;
  std::vector<Ipv4Address> m_ips;
  uint32_t m_index;
  EventId m_sendEvent;
};

void PrintFinalResults()
{
  NS_LOG_INFO("PrintFinalResults called at " << Simulator::Now().GetSeconds() << "s");
  double pdr = g_totalLegitSent ? 100.0 * g_totalLegitReceived / g_totalLegitSent : 0.0;

  std::cout << std::fixed << std::setprecision(2);
  std::cout << "\n=== SYBIL ATTACK DEFENCE SIMULATION RESULTS ===\n";
  std::cout << "Legitimate packets sent:     " << g_totalLegitSent << "\n";
  std::cout << "Legitimate packets received: " << g_totalLegitReceived << "\n";
  std::cout << "Packet Delivery Ratio (PDR): " << pdr << " %\n";
  std::cout << "Attack packets sent:         " << g_attackPacketsSent << "\n";
  std::cout << "Attack packets dropped:      " << g_attackPacketsDropped << "\n";
  std::cout << "================================\n";

  g_detector->PrintReport();

  if (pdr > 90.0)
    std::cout << "Network status: WELL PROTECTED\n";
  else if (pdr > 70.0)
    std::cout << "Network status: PARTIALLY PROTECTED\n";
  else
    std::cout << "Network status: VULNERABLE\n";

  std::cout << std::flush;
}

int main(int argc, char *argv[])
{
  uint32_t nNodes = 10;
  uint32_t sybilCount = 6;
  bool enablePcap = true;

  CommandLine cmd;
  cmd.AddValue("nNodes", "Number of legitimate nodes", nNodes);
  cmd.AddValue("sybilCount", "Number of Sybil identities", sybilCount);
  cmd.AddValue("enablePcap", "Enable PCAP capture", enablePcap);
  cmd.Parse(argc, argv);

  LogComponentEnable("SybilDefenseSimulation", LOG_LEVEL_INFO);

  g_detector = CreateObject<SybilDetector>();

  NodeContainer nodes;
  nodes.Create(nNodes + 1);
  Ptr<Node> attacker = nodes.Get(nNodes);

  NodeContainer legitNodes;
  for (uint32_t i = 0; i < nNodes; ++i)
    legitNodes.Add(nodes.Get(i));

  InternetStackHelper internet;
  AodvHelper aodv;
  internet.SetRoutingHelper(aodv);
  internet.Install(nodes);

  MobilityHelper mobility;
  mobility.SetPositionAllocator("ns3::GridPositionAllocator",
                                "MinX", DoubleValue(-100.0),
                                "MinY", DoubleValue(-100.0),
                                "DeltaX", DoubleValue(50.0),
                                "DeltaY", DoubleValue(50.0),
                                "GridWidth", UintegerValue(5),
                                "LayoutType", StringValue("RowFirst"));
  mobility.SetMobilityModel("ns3::RandomWalk2dMobilityModel",
                            "Bounds", RectangleValue(Rectangle(-100, 150, -100, 150)),
                            "Speed", StringValue("ns3::UniformRandomVariable[Min=0.5|Max=1.0]"));
  mobility.Install(legitNodes);

  MobilityHelper mobAttacker;
  mobAttacker.SetMobilityModel("ns3::ConstantPositionMobilityModel");
  mobAttacker.Install(attacker);
  attacker->GetObject<MobilityModel>()->SetPosition(Vector(300, 300, 0));

  WifiHelper wifi;
  wifi.SetStandard(WIFI_STANDARD_80211b);
  wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                              "DataMode", StringValue("DsssRate2Mbps"),
                              "ControlMode", StringValue("DsssRate1Mbps"));

  YansWifiChannelHelper channel = YansWifiChannelHelper::Default();
  YansWifiPhyHelper phy;
  phy.SetChannel(channel.Create());

  WifiMacHelper mac;
  mac.SetType("ns3::AdhocWifiMac");

  NetDeviceContainer devices = wifi.Install(phy, mac, nodes);

  Ptr<NetDevice> attackerDev = devices.Get(nNodes);
  Ptr<WifiNetDevice> wifiDev = DynamicCast<WifiNetDevice>(attackerDev);
  if (wifiDev)
  {
    Ptr<YansWifiPhy> attackerPhy = DynamicCast<YansWifiPhy>(wifiDev->GetPhy());
    if (attackerPhy)
    {
      attackerPhy->SetTxPowerStart(40.0);
      attackerPhy->SetTxPowerEnd(40.0);
    }
  }

  Ipv4AddressHelper ipAddr;
  ipAddr.SetBase("10.0.0.0", "255.255.255.0");
  Ipv4InterfaceContainer interfaces = ipAddr.Assign(devices);

  UdpEchoServerHelper server(9);
  ApplicationContainer serverApps = server.Install(nodes.Get(0));
  serverApps.Start(Seconds(1.0));
  serverApps.Stop(Seconds(120.0));

  UdpEchoClientHelper client(interfaces.GetAddress(0), 9);
  client.SetAttribute("MaxPackets", UintegerValue(100));
  client.SetAttribute("Interval", TimeValue(Seconds(0.8)));
  client.SetAttribute("PacketSize", UintegerValue(1024));
  ApplicationContainer clientApps = client.Install(nodes.Get(1));
  clientApps.Start(Seconds(2.0));
  clientApps.Stop(Seconds(120.0));

  clientApps.Get(0)->TraceConnectWithoutContext("Tx", MakeCallback(&LogLegitTx));
  serverApps.Get(0)->TraceConnectWithoutContext("Rx", MakeCallback(&LogLegitRx));

  for (uint32_t i = 0; i < nNodes; ++i)
  {
    Ptr<Ipv4> ipv4 = nodes.Get(i)->GetObject<Ipv4>();
    ipv4->TraceConnectWithoutContext("Rx", MakeCallback(&DefenseRxCallback));
  }

  Ptr<SybilApp> attackerApp = CreateObject<SybilApp>();
  attackerApp->Setup(attacker, sybilCount);
  attacker->AddApplication(attackerApp);
  attackerApp->SetStartTime(Seconds(15.0));
  attackerApp->SetStopTime(Seconds(120.0));

  if (enablePcap)
    phy.EnablePcapAll("sybil-defense");

  AnimationInterface anim("sybil-defense.xml");
  for (uint32_t i = 0; i < nNodes; i++)
  {
    anim.UpdateNodeColor(nodes.Get(i), 0, 255, 0);
    anim.UpdateNodeSize(nodes.Get(i)->GetId(), 25, 25);
  }
  anim.UpdateNodeColor(attacker, 255, 0, 0);
  anim.UpdateNodeSize(attacker->GetId(), 50, 50);

  Simulator::Schedule(Seconds(121.0), &PrintFinalResults);
  Simulator::Stop(Seconds(121.0));

  Simulator::Run();

  std::cout << "Simulation completed." << std::endl << std::flush;

  Simulator::Destroy();

  return 0;
}
