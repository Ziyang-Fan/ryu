Prerequisites:
 - Must be on a linux machine with the following:
    :: Mininet
    :: Openflow13 or above (OpenvSwitch 2.3 or above)
    :: Python3

How to run:
    - If you'd like to run the controller separate from the simulation:
        :: run `sh ./run_controller.sh` to boot controller
        :: run `bash ./run_mininet.sh` to boot the simulation
          - Note: you may have to edit the IP if you're not running the controller on the same machine

    - If you'd like to run the benchmark:
        :: run `sh ./run_benchmark.sh` to run the benchmark
          - Note: While you can run the py script directly, it still requires linux

Consult the user manual for a more comprehensive installation guide
