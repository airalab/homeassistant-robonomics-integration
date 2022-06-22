FROM ghcr.io/home-assistant/home-assistant:stable
RUN /bin/bash -c 'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | bash -s -- -y'
RUN /bin/bash -c 'source $HOME/.cargo/env; rustup default nightly'
RUN pip3 install http3==0.6.7