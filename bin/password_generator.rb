#!/usr/bin/env ruby

require "optparse"

#require "password_generator"
require "./lib/password_generator"

PasswordGenerator::Runner.from_argv(ARGV).run
