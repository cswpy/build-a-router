# L2 MAC Learning Controller

This l2switch forwards ARP requests/replies to a controller that learns the
MAC/port mappings and installs the appropriate table entries.

## Running

First, make sure you have p4app (which requires Docker):

    cd ~/
    git clone --branch rc-2.0.0 https://github.com/p4lang/p4app.git

Then run this p4app:

    ~/p4app/p4app run maclearning.p4app
