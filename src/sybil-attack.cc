#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/wifi-module.h"
#include "ns3/aodv-module.h"
#include "ns3/applications-module.h"
#include "ns3/netanim-module.h"
#include "ns3/ipv4-raw-socket-factory.h"
#include <sstream>
#include <vector>
#include <iomanip>
#include <iostream>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("SybilAttackSimulation");

// --- Global variables for statistics ---
uint32_t g_totalSent = 0;
uint32_t g_totalReceived = 0;
uint32_t g_sybilPacketsSent = 0;
uint32_t g_sybilPacketsReceived = 0;

// Global list of all Sybil IPs for reliable detection
std::vector<Ipv4Address> g_sybilIpAddresses;

// --- Attacker Application ---
class SybilNodeApp : public Application
{
private:
    struct SybilIdentity {
        Ipv4Address ipAddress;
    };

public:
    SybilNodeApp() : m_currentSybilIndex(0) {}
    virtual ~SybilNodeApp() {}

    void Setup(Ptr<Node> node, uint32_t numSybilIds)
    {
        m_node = node;
        g_sybilIpAddresses.clear();
        for (uint32_t i = 0; i < numSybilIds; i++) {
            SybilIdentity id;
            std::ostringstream oss;
            oss << "10.0.0." << (200 + i); // Define fake IP range
            id.ipAddress = Ipv4Address(oss.str().c_str());
            m_sybilIdentities.push_back(id);
            g_sybilIpAddresses.push_back(id.ipAddress);
        }
    }

private:
    virtual void StartApplication(void) override
    {
        m_rawSocket = Socket::CreateSocket(m_node, Ipv4RawSocketFactory::GetTypeId());
        m_rawSocket->SetAllowBroadcast(true);
        Simulator::Schedule(Seconds(1.0), &SybilNodeApp::ExecuteAttack, this);
    }

    void ExecuteAttack()
    {
        const SybilIdentity& identity = m_sybilIdentities[m_currentSybilIndex];
        SendSybilPacket(identity);
        m_currentSybilIndex = (m_currentSybilIndex + 1) % m_sybilIdentities.size();
        Simulator::Schedule(Seconds(0.8), &SybilNodeApp::ExecuteAttack, this);
    }

    void SendSybilPacket(const SybilIdentity& identity)
    {
        g_sybilPacketsSent++;
        Ptr<Packet> payload = Create<Packet>(128);

        Ipv4Header ipv4Header;
        ipv4Header.SetSource(identity.ipAddress); // IP Spoofing
        ipv4Header.SetDestination(Ipv4Address("255.255.255.255"));
        ipv4Header.SetProtocol(17); // UDP
        payload->AddHeader(ipv4Header);

        m_rawSocket->Send(payload);

        NS_LOG_INFO(Simulator::Now().GetSeconds() << "s: Sybil packet SENT from spoofed IP " << identity.ipAddress);
    }

    Ptr<Socket> m_rawSocket;
    Ptr<Node> m_node;
    std::vector<SybilIdentity> m_sybilIdentities;
    uint32_t m_currentSybilIndex;
};

// --- Trace Callbacks ---
void TxTrace(Ptr<const Packet>) { g_totalSent++; }
void RxTrace(Ptr<const Packet>) { g_totalReceived++; }

void Ipv4RxTrace(Ptr<const Packet> packet, Ptr<Ipv4> ipv4, uint32_t interface)
{
    Ipv4Header header;
    if (packet->PeekHeader(header)) {
        Ipv4Address src = header.GetSource();
        for (const auto& sybilIp : g_sybilIpAddresses) {
            if (src == sybilIp) {
                g_sybilPacketsReceived++;
                NS_LOG_INFO(Simulator::Now().GetSeconds() << "s: Sybil packet RECEIVED from " << src
                            << " at Node " << ipv4->GetObject<Node>()->GetId());
                break; // Found a match
            }
        }
    }
}

// --- Statistics Printing ---
void PrintFinalStatistics()
{
    double pdr = (g_totalSent > 0) ? (double)g_totalReceived / g_totalSent * 100.0 : 0.0;
    std::cout << "\n============ SYBIL ATTACK SIMULATION RESULTS ============\n";
    std::cout << "Legitimate Traffic:\n";
    std::cout << "  Packets Sent:     " << g_totalSent << "\n";
    std::cout << "  Packets Received: " << g_totalReceived << "\n";
    std::cout << "  PDR:              " << std::fixed << std::setprecision(2) << pdr << " %\n";
    std::cout << "---------------------------------------------------------\n";
    std::cout << "Attack Impact:\n";
    std::cout << "  Sybil Pkts Sent:  " << g_sybilPacketsSent << "\n";
    std::cout << "  Sybil Pkts Rx'd:  " << g_sybilPacketsReceived << "\n";
    std::cout << "=========================================================\n";
}

int main(int argc, char *argv[])
{
    uint32_t nNodes = 10;
    uint32_t numSybilIds = 6;
    bool enablePcap = true;

    CommandLine cmd(__FILE__);
    cmd.AddValue("nNodes", "Number of legitimate nodes", nNodes);
    cmd.AddValue("numSybilIds", "Number of Sybil identities", numSybilIds);
    cmd.AddValue("enablePcap", "Enable PCAP tracing", enablePcap);
    cmd.Parse(argc, argv);

    LogComponentEnable("SybilAttackSimulation", LOG_LEVEL_INFO);

    NodeContainer allNodes;
    allNodes.Create(nNodes + 1);
    Ptr<Node> maliciousNode = allNodes.Get(nNodes);
    NodeContainer legitimateNodes;
    for (uint32_t i = 0; i < nNodes; ++i) {
        legitimateNodes.Add(allNodes.Get(i));
    }

    InternetStackHelper internet;
    AodvHelper aodv;
    internet.SetRoutingHelper(aodv);
    internet.Install(allNodes);

    MobilityHelper mobility;
    mobility.SetPositionAllocator("ns3::GridPositionAllocator",
                                  "MinX", DoubleValue(100.0), "MinY", DoubleValue(100.0),
                                  "DeltaX", DoubleValue(80.0), "DeltaY", DoubleValue(80.0),
                                  "GridWidth", UintegerValue(5), "LayoutType", StringValue("RowFirst"));
    mobility.SetMobilityModel("ns3::RandomWalk2dMobilityModel",
                              "Bounds", RectangleValue(Rectangle(50, 550, 50, 550)),
                              "Speed", StringValue("ns3::UniformRandomVariable[Min=1.0|Max=4.0]"),
                              "Distance", DoubleValue(80.0));
    mobility.Install(legitimateNodes);

    MobilityHelper maliciousMobility;
    maliciousMobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    maliciousMobility.Install(maliciousNode);
    maliciousNode->GetObject<MobilityModel>()->SetPosition(Vector(300.0, 300.0, 0.0));

    WifiHelper wifi;
    wifi.SetStandard(WIFI_STANDARD_80211b);
    wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                                 "DataMode", StringValue("DsssRate2Mbps"),
                                 "ControlMode", StringValue("DsssRate1Mbps"));

    YansWifiChannelHelper channel = YansWifiChannelHelper::Default();
    YansWifiPhyHelper phyHelper;
    phyHelper.SetChannel(channel.Create());
    WifiMacHelper mac;
    mac.SetType("ns3::AdhocWifiMac");
    NetDeviceContainer devices = wifi.Install(phyHelper, mac, allNodes);

    // Increase transmission power for attacker device
    Ptr<NetDevice> maliciousDevice = devices.Get(nNodes);
    Ptr<WifiNetDevice> maliciousWifiDevice = DynamicCast<WifiNetDevice>(maliciousDevice);
    if (maliciousWifiDevice) {
        Ptr<YansWifiPhy> maliciousPhy = DynamicCast<YansWifiPhy>(maliciousWifiDevice->GetPhy());
        if (maliciousPhy) {
            maliciousPhy->SetTxPowerStart(40.0);
            maliciousPhy->SetTxPowerEnd(40.0);
        }
    }

    Ipv4AddressHelper ipv4;
    ipv4.SetBase("10.0.0.0", "255.255.255.0");
    Ipv4InterfaceContainer interfaces = ipv4.Assign(devices);

    // Legitimate UDP traffic generation
    UdpEchoServerHelper echoServer(9);
    ApplicationContainer serverApps = echoServer.Install(allNodes.Get(0));
    serverApps.Start(Seconds(1.0));
    serverApps.Stop(Seconds(120.0));

    UdpEchoClientHelper echoClient(interfaces.GetAddress(0), 9);
    echoClient.SetAttribute("MaxPackets", UintegerValue(150));
    echoClient.SetAttribute("Interval", TimeValue(Seconds(0.8)));
    echoClient.SetAttribute("PacketSize", UintegerValue(1024));
    ApplicationContainer clientApps = echoClient.Install(allNodes.Get(1));
    clientApps.Start(Seconds(2.0));
    clientApps.Stop(Seconds(120.0));

    // Connect traces for legitimate traffic
    clientApps.Get(0)->TraceConnectWithoutContext("Tx", MakeCallback(&TxTrace));
    serverApps.Get(0)->TraceConnectWithoutContext("Rx", MakeCallback(&RxTrace));

    // Connect sybil detection trace on legitimate nodes IPv4 Rx
    for (uint32_t i = 0; i < nNodes; i++) {
        Config::ConnectWithoutContext(
            "/NodeList/" + std::to_string(i) + "/$ns3::Ipv4L3Protocol/Rx",
            MakeCallback(&Ipv4RxTrace)
        );
    }

    // Setup and start the Sybil attack application
    Ptr<SybilNodeApp> sybilApp = CreateObject<SybilNodeApp>();
    sybilApp->Setup(maliciousNode, numSybilIds);
    maliciousNode->AddApplication(sybilApp);
    sybilApp->SetStartTime(Seconds(3.0));
    sybilApp->SetStopTime(Seconds(120.0));

    if (enablePcap) {
        phyHelper.EnablePcapAll("sybil-attack");
    }

    // NetAnim Visualization
    AnimationInterface anim("sybil-attack.xml");
    for (uint32_t i = 0; i < nNodes; ++i) {
        anim.UpdateNodeColor(allNodes.Get(i), 0, 255, 0);
        anim.UpdateNodeSize(allNodes.Get(i)->GetId(), 25, 25);
    }
    anim.UpdateNodeColor(maliciousNode, 255, 0, 0);
    anim.UpdateNodeSize(maliciousNode->GetId(), 50, 50);

    // Run Simulation
    Simulator::Stop(Seconds(125.0));
    Simulator::Schedule(Seconds(121.0), &PrintFinalStatistics);
    Simulator::Run();
    Simulator::Destroy();

    return 0;
}
