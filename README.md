## Generate Gemfile.lock

Whenever the dependencies in Gemfile change, a new Gemfile.lock file should be
created using the following command:

    $ docker run --rm -v "$PWD":/usr/src/app -w /usr/src/app ruby:2.2 \
      bundle install

## Building Docker image

    $ docker build -t rattrace-udp .

## Running Docker container

This container links with the RatTrace server container, so make sure you run
that first.

    $ docker run --rm -it --link rattrace-server-inst:dest -p 9252:9252/udp \
      --name rattrace-udp-inst rattrace-udp
