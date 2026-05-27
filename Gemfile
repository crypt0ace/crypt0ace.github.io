# frozen_string_literal: true

source "https://rubygems.org"

gem "jekyll-theme-chirpy", "~> 7.5", ">= 7.5.0"

group :test do
  gem "html-proofer", "~> 5.0"
end

install_if -> { RUBY_PLATFORM =~ %r!mingw|mswin|java! } do
  gem "tzinfo"
  gem "tzinfo-data"
end

gem "wdm", "~> 0.2", :install_if => Gem.win_platform?

gem "webrick", "~> 1.8"