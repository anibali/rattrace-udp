FROM ruby:2.2

# Enforce up-to-date Gemfile.lock
RUN bundle config --global frozen 1

RUN mkdir -p /usr/src/app
WORKDIR /usr/src/app

COPY Gemfile /usr/src/app/
COPY Gemfile.lock /usr/src/app/
RUN bundle install

COPY . /usr/src/app

# TODO: Move all of this to external config
ENV DEST_USER udp_server
ENV DEST_PASS super_secret_password

EXPOSE 9252
CMD ["./lib/udp_server.rb"]
