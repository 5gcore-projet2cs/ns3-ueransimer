#!/bin/sh

# Install the necessary dependencies for ns3-ueransimer
sudo apt update
sudo apt install g++ python3 cmake ninja-build git gir1.2-goocanvas-2.0 python3-gi python3-gi-cairo python3-pygraphviz gir1.2-gtk-3.0 ipython3 tcpdump wireshark libsqlite3-dev qtbase5-dev qtchooser qt5-qmake qtbase5-dev-tools openmpi-bin openmpi-common openmpi-doc libopenmpi-dev doxygen graphviz imagemagick python3-sphinx dia imagemagick texlive dvipng latexmk texlive-extra-utils texlive-latex-extra texlive-font-utils libeigen3-dev gsl-bin libgsl-dev libgslcblas0 libxml2 libxml2-dev libgtk-3-dev lxc-utils lxc-templates vtun uml-utilities ebtables bridge-utils libxml2 libxml2-dev libboost-all-dev ccache build-essential autoconf automake libxmu-dev sqlite3 build-essential autoconf automake libxmu-dev

# Clone the ns3-ueransimer repository and build it
git clone https://github.com/5gcore-projet2cs/ns3-ueransimer.git
cd ns3-ueransimer
./ns3 configure --enable-examples --enable-tests
./ns3 build
