
from lib import config # do not import anything before this
from p4app import P4Mininet
from mininet.topo import Topo
from mininet.cli import CLI
import os
 
NUM_WORKERS = 4 # TODO: Make sure your program can handle larger values
 
class SMLTopo(Topo):
    def __init__(self, **opts):
        Topo.__init__(self, **opts)
        # TODO: Implement me. Feel free to modify the constructor signature
        # NOTE: Make sure worker names are consistent with RunWorkers() below
        sw = self.addSwitch('s1')
        for i in range(NUM_WORKERS):
            host_name = 'w%d' % i
            worker = self.addHost(
                host_name,
                ip="10.0.0.%d/24" % (i + 1),
                mac="00:00:00:00:01:%02x" % (i + 1)
            )
            self.addLink(worker, sw, port2=i) # Switch port index matches worker rank
 
 
def RunWorkers(net):
    """
    Starts the workers and waits for their completion.
    Redirects output to logs/<worker_name>.log (see lib/worker.py, Log())
    This function assumes worker i is named 'w<i>'. Feel free to modify it
    if your naming scheme is different
    """
    worker = lambda rank: "w%i" % rank
    log_file = lambda rank: os.path.join(os.environ['APP_LOGS'], "%s.log" % worker(rank))
    for i in range(NUM_WORKERS):
        net.get(worker(i)).sendCmd('python worker.py %d > %s' % (i, log_file(i)))
    for i in range(NUM_WORKERS):
        net.get(worker(i)).waitOutput()
    print("All workers have completed their execution.")    
 
def RunControlPlane(net):
    """
    One-time control plane configuration
    """
    # TODO: Implement me (if needed)
    print("Configuring control plane...")
    s1 = net.get('s1')
 
    # configure the multicast group
    # ALL_WORKERS_MCAST_GROUP = 1 corresponding to the P4 program
    mc_ports = [i for i in range(NUM_WORKERS)]
    s1.addMulticastGroup(mgid=1, ports=mc_ports)
    print("Multicast group 1 configured with ports:", mc_ports)
 
 
topo = SMLTopo() # TODO: Create an SMLTopo instance
net = P4Mininet(program="p4/main.p4", topo=topo)
net.run_control_plane = lambda: RunControlPlane(net)
net.run_workers = lambda: RunWorkers(net)
net.start()
net.run_control_plane()
CLI(net)
net.stop()
