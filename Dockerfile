# Use Ruby 2.7 on Debian Buster
FROM ruby:2.7-buster

# Install dependencies required for building native gems
RUN apt-get update && apt-get install -y \
  build-essential \
  git \
  nodejs \
  && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /site

# Copy project files into container
COPY . .

# Install bundler & gems
RUN gem install bundler:2.1.4
RUN bundle config set --local path 'vendor/bundle'
RUN bundle install

# Expose Jekyll server port
EXPOSE 4000

# Default command (can be overridden)
CMD ["bundle", "exec", "jekyll", "serve", "--host", "0.0.0.0"]

