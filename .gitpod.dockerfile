FROM gitpod/workspace-full

RUN sudo apt-get update \
 && sudo apt-get install -y \
    valgrind \
    electric-fence \
    doxygen \
 && sudo rm -rf /var/lib/apt/lists/*
