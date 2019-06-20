from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.util import dumpNodeConnections
from mininet.cli import CLI
import subprocess as sp
import time
import re
import pprint
import json
import datetime
import os

from mininet.util import (waitListening)

from lib.topo import topos
from lib.controller import MultipathController, MAX_MULTIPATHS


class MininetApp():
    """The benchmarking mininet application

    Parameters
    ----------


    Attributes
    ----------
    controller : type
        Keeps a handle on the current active controller object
    mininet_clear : type
        Keeps a handle on the current active mininet object
    pp : type
        This is the pretty printer object with custom formatting
    results_path : type
        This is the results folder location
    nhop_results : type
        Contains results for hhop iterations
    rxtx_re : type
        Regular expression for capturing rx and tx patterns
    ports_re : type
        Regular expression for capturing ports on a switch
    max_multipaths : type
        The maximum number of paths used in multipath
    topos_to_benchmark : type
        A custom dictioned designed to test topologies

    """

    def __init__(self):
        """Setups the benchmark automator.

        Parameters
        ----------


        Returns
        -------
        None
            None

        """
        self.controller = None
        self.mininet_clear = None
        self.pp = pprint.PrettyPrinter(indent=4)
        self.results_path = os.getcwd() + '/results'
        self.nhop_results = {}
        self.rxtx_re = re.compile(r'[t|r]x pkts=\d*')
        self.ports_re = re.compile(r'port\s*\d')
        self.max_multipaths = MAX_MULTIPATHS
        self.topos_to_benchmark = {
            'default': {
                'topo': 'default_multipath',
                'best_case': 1,
                'worst_case': 2,
                'watch_switch': 's5',
                'ports': [1, 2]
            },
            'data_centre': {
                'topo': 'data_centre_multipath',
                'best_case': 0,
                'worst_case': 5,
                'watch_switch': 's5',
                'ports': [1, 2, 3]
            },
            'default_no_limit': {
                'topo': 'default_no_limits',
                'best_case': 1,
                'worst_case': 2,
                'custom_n_hop': 'n_hop_case_no_limits',
                'watch_switch': 's5',
                'ports': [1, 2]
            }
        }

        # Boot the program and wipe any leaking mn data
        self.clear_mininet()
        self.wait_mininet()

        print 'Antony Kimpton\'s Mininet Application...'

    def run_benchmarks(self, iperf_iterations=3, iperf_duration=30):
        """Runs all the benchmarks with custom iterations and duration.

        Parameters
        ----------
        iperf_iterations : int
            number of iterations to obtain from iperf
        iperf_duration : int
            the duration in seconds of iperf executing

        Returns
        -------
        None
            None

        """
        speed_results = {}

        for topo_category in self.topos_to_benchmark:
            if topo_category not in speed_results:
                speed_results[topo_category] = {}

            multipath = self.topos_to_benchmark[topo_category]['topo']
            best_case = self.topos_to_benchmark[topo_category]['best_case']
            worst_case = self.topos_to_benchmark[topo_category]['worst_case']

            n_hop = 'n_hop_case'
            if 'custom_n_hop' in self.topos_to_benchmark[topo_category]:
                n_hop = self.topos_to_benchmark[topo_category]['custom_n_hop']

            # Keep track of nhop tests that need to be ran
            local_nhop_tests = []

            if n_hop not in self.nhop_results:
                self.nhop_results[n_hop] = {}

            if best_case not in self.nhop_results[n_hop]:
                local_nhop_tests.append(best_case)

            if worst_case not in self.nhop_results[n_hop] and worst_case \
                    != best_case:
                local_nhop_tests.append(worst_case)

            # Run the speed test
            print'\n\n\nRunning multipath speed tests for {}\n\n\n'.\
                format(multipath)
            speed_result, port_data = self.benchmark_topo(
                topo=topos[multipath](),
                iperf_iterations=iperf_iterations,
                iperf_duration=iperf_duration,
                watch_switch=self.topos_to_benchmark
                [topo_category]['watch_switch'],
                ports=self.topos_to_benchmark[topo_category]['ports']
            )
	    print "**************"
	    print topos[multipath]()
	    print "*************"
            # Run iperf for new nhop cases
            for nhop_test in local_nhop_tests:
                print '\n\n\nRunning single path speed tests for {}\n\n\n'.\
                    format(multipath)
                self.nhop_results[n_hop][nhop_test], ignore = \
                    self.benchmark_topo(
                    topo=topos[n_hop](n=nhop_test),
                    iperf_iterations=iperf_iterations,
                    iperf_duration=iperf_duration
                )
	    print "IIIIIIIIIIIIIII"
	    print topos[n_hop](n=nhop_test)
	    print "IIIIIIIIIIIIIII"
            bc_speed_result = self.nhop_results[n_hop][best_case]
            wc_speed_result = self.nhop_results[n_hop][worst_case]

            avg_multipath_speed = 0
            avg_bc_speed = 0
            avg_wc_speed = 0
            for i in range(0, iperf_iterations):
                # Take the client speed
                avg_multipath_speed += float(speed_result[i][1].split(' ')[0])
                avg_bc_speed += float(bc_speed_result[i][1].split(' ')[0])
                avg_wc_speed += float(wc_speed_result[i][1].split(' ')[0])

            avg_multipath_speed = avg_multipath_speed / iperf_iterations
            avg_bc_speed = avg_bc_speed / iperf_iterations
            avg_wc_speed = avg_wc_speed / iperf_iterations
            best_single_route_speed = max(avg_bc_speed, avg_wc_speed)

            speed_increase = avg_multipath_speed / best_single_route_speed
            speed_increase = round(speed_increase, 2)  # round to 2dp

            # Rx Tx load balance
            load_balance = {}
            all_rx = []
            all_tx = []
            for i, port in enumerate(port_data):
                rx_tx = port_data[port]
                if i < self.max_multipaths:
                    all_rx.append(rx_tx['rx'])
                    all_tx.append(rx_tx['tx'])
            total_rx = sum(all_rx)
            total_tx = sum(all_tx)
            for i, port in enumerate(port_data):
                rx_tx = port_data[port]
                if i < self.max_multipaths:
                    load_balance[port] = {
                        'rx': round(100 * rx_tx['rx'] / total_rx),
                        'tx': round(100 * rx_tx['rx'] / total_rx)
                    }

            # Update the results
            speed_results[topo_category]['multipath'] = speed_result
            speed_results[topo_category]['best_case'] = bc_speed_result
            speed_results[topo_category]['worst_case'] = wc_speed_result
            speed_results[topo_category]['speed_increase'] = speed_increase
            speed_results[topo_category]['multipath_load_balance'] = \
                load_balance
        # Print results
        self.pp.pprint(speed_results)
        self.write_results(speed_results)

    def run_iperf(self, hosts=None, l4Type='TCP', udpBw='10M', fmt=None,
                  seconds=5, port=5001, args='', net=None):
        """
        This is an copy of the Mininet.net.Mininet.iperf(...) function,
        with addition to add some custom args to the connection command

        This code belongs to Mininet, and has only been adapted to work for this
        use case

        Parameters
        ----------
        hosts : type
            Description of parameter `hosts`.
        l4Type : type
            Description of parameter `l4Type`.
        udpBw : type
            Description of parameter `udpBw`.
        fmt : type
            Description of parameter `fmt`.
        seconds : type
            Description of parameter `seconds`.
        port : type
            Description of parameter `port`.
        args : type
            Description of parameter `args`.
        net : type
            Description of parameter `net`.

        Returns
        -------
        type
            Description of returned object.

        """
        '''
        This is an copy of the Mininet.net.Mininet.iperf(...) function,
        with addition to add some custom args to the connection command
        '''
        hosts = hosts or [net.hosts[0], net.hosts[-1]]
        assert len(hosts) == 2
        client, server = hosts

        server.cmd('killall -9 iperf')
        iperfArgs = 'iperf -p %d ' % port
        bwArgs = ''
        if l4Type == 'UDP':
            iperfArgs += '-u '
            bwArgs = '-b ' + udpBw + ' '
        elif l4Type != 'TCP':
            print 'Unexpected l4 type: %s' % l4Type
        if fmt:
            iperfArgs += '-f %s ' % fmt
        server.sendCmd(iperfArgs + '-s')
        if l4Type == 'TCP':
            if not waitListening(client, server.IP(), port):
                print 'Could not connect to iperf on port %d' % port
        cliout = client.cmd(iperfArgs + '-t %d -c ' % seconds +
                            server.IP() + ' ' + bwArgs + ' ' + args )

        servout = ''
        # We want the last *b/sec from the iperf server output
        # for TCP, there are two of them because of waitListening
        count = 2 if l4Type == 'TCP' else 1
        while len(re.findall('/sec', servout)) < count:
            servout += server.monitor(timeoutms=5000)
        server.sendInt()
        servout += server.waitOutput()

        result = [net._parseIperf(servout), net._parseIperf(cliout)]
        if l4Type == 'UDP':
            result.insert(0, udpBw)

        return result

    def benchmark_topo(self, topo, cli=False, xterms=False, iperf_iterations=3,
                       iperf_duration=30, watch_switch=None, ports=None):
        """This function runs the desired topo and pings all the hosts

        Parameters
        ----------
        topo : str
            Description of parameter `topo`.
        cli : bool
            Description of parameter `cli`.
        xterms : bool
            Description of parameter `xterms`.
        iperf_iterations : int
            Description of parameter `iperf_iterations`.
        iperf_duration : int
            Description of parameter `iperf_duration`.

        Returns
        -------
        list
            Speed of Client:Server as [client, server]

        """
        # Boot the controller
        self.run_controller()

        # Setup and run the simulation environment
        net = Mininet(topo=topo, controller=RemoteController,
                      switch=OVSKernelSwitch, xterms=xterms)
        net.start()

        # This will build all the multipath route flow tables (Not required)
        net.pingAll()

        # Run the network performance test -P allows for simaltanous connections
        speed = []
        for i in range(0, iperf_iterations):
            print 'Running IPerf with duration {} seconds and iteration {}/{}'\
                .format(iperf_duration, i + 1, iperf_iterations)
            speed.append(self.run_iperf(
                seconds=iperf_duration, net=net, args='-P 4'))

        # If cli mode is checked, allows user to access the environment
        if cli:
            CLI(net)

        port_data = None
        if watch_switch and ports:
            port_data = self.get_switch_port_data(switch=watch_switch)

        # Shutdowns the network
        net.stop()
        # Closes the network and waits for it to finish
        self.clear_mininet()
        self.wait_controller()
        self.wait_mininet()

        # Returns the benchmark
        return (speed, port_data)

    def wait_mininet(self):
        '''
        If there is a mininet clear occuring, it will wait till it finishes
        '''
        if self.mininet_clear:
            self.mininet_clear.wait()
            self.mininet_clear = None

    def wait_controller(self):
        '''
        If there is a controller occuring, it will wait till it finishes
        '''
        if self.controller:
            self.controller.wait()
            self.controller = None

    def get_switch_port_data(self, switch=None):
        """Obtains data about the ports used and the distribution of packets
        on a switch

        Parameters
        ----------
        switch : String
            The id of the switch

        Returns
        -------
        dictionary
            Returns the rxtx data indexed by their ports

        """

        # Runs the dump-ports command on a switch and obtains the results
        if switch:
            try:
                command = 'ovs-ofctl -O OpenFlow13 dump-ports ' + switch
                process = sp.Popen(
                    command.split(' '), stdout=sp.PIPE)
                out, err = process.communicate()
                out = out.decode("utf-8")

                # The following code pulls out the ports and the
                # respective rxtx data
                pkt_results = self.rxtx_re.findall(out)
                port_order = self.ports_re.findall(out)
                port_num = [int(port_match.split('  ')[1])
                            for port_match in port_order]
                rxtx = {}
                for i in range(0, len(port_order) + 1):
                    matchrx = int(pkt_results[2 * i].split('=')[1])
                    matchtx = int(pkt_results[(2 * i) + 1].split('=')[1])
                    port = 'LOCAL'
                    if i != 0:
                        port = port_num[i - 1]
                    rxtx[port] = {
                        'rx': matchrx,
                        'tx': matchtx
                    }

                # Returns packet data: eg. rxtx[port_number] = {'rx': 101,
                # 'tx': 102}
                return rxtx
            except:
                return None

    def clear_mininet(self):
        '''
        Runs a sudo mn -c to clean any mininet data
        '''
        self.mininet_clear = sp.Popen(['mn', '-c'])

    def run_controller(self, force=False, silent=True):
        '''
        Runs the controller and sets its thread to self.controller
            if a controller is running, it will not boot another
            unless the force flag is set to True
        '''
        if not self.controller or force:
            print 'Booting Controller...'
            # If forced, assume the program is hung
            if force:
                self.clear_mininet()
                self.wait_mininet()

            controller = None
            if silent:
                controller = sp.Popen(['ryu-manager', '--observe-links',
                                       './lib/controller.py'],
                                      shell=False, stdout=sp.PIPE)
            else:
                controller = sp.Popen(
                    ['ryu-manager', '--observe-links', './lib/controller.py'])

            self.controller = controller
            time.sleep(5)  # Required as we have to wait for boot sequence
            print 'Controller booted!'

    def write_results(self, results):
        """Writes diction results to a json file

        Parameters
        ----------
        results : dictionary
            a dictionary to be saved as a file

        Returns
        -------
        None
            None

        """
        date_time = datetime.datetime.now().strftime("%Y-%m-%d %H%M")
        file_name = 'Mininet Benchmark - ' + date_time + '.json'
        file = self.results_path + '/' + file_name
        with open(file, 'w') as f:
            json.dump(results, f, indent=2)


if __name__ == '__main__':
    setLogLevel('info')
    mininet_app = MininetApp()
    mininet_app.run_benchmarks(iperf_iterations=3, iperf_duration=10)

