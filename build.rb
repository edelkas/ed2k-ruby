#!/usr/bin/env ruby
# frozen_string_literal: true

# Rebuild the native extension and, optionally, test the gem. Runs the same on Windows, Linux and macOS,
# so there's no need to remember a different incantation per machine.
#
#   ruby build.rb            Compile the extension and drop the fresh binary into lib/.
#   ruby build.rb test       ...then run the whole test suite.
#   ruby build.rb console    ...then open an IRB session with the gem already loaded (as ED2K).
#   ruby build.rb clean      Remove the compiled binary and all build leftovers, then stop.
#
# The point is that `require 'ed2k'` in lib/ picks up whatever this script just built, so the usual
# develop loop is: edit ext/*.c, run this, test. It replaces hand-copying the .so, which only worked
# on one OS and skipped steps like regenerating the Makefile after extconf.rb or the compiler flags
# changed.

require 'rbconfig'
require 'fileutils'

ROOT     = __dir__
EXT_DIR  = File.join(ROOT, 'ext')
LIB_DIR  = File.join(ROOT, 'lib')
EXTNAME  = 'ced2k'                                     # Must match create_makefile(...) in ext/extconf.rb
DLEXT    = RbConfig::CONFIG['DLEXT']                   # Native library suffix for this platform (so, bundle, dll)
BINARY   = "#{EXTNAME}.#{DLEXT}"
WINDOWS  = RbConfig::CONFIG['host_os'] =~ /mingw|mswin/
MAKE     = ENV['MAKE'] || RbConfig::CONFIG['MAKE'] || (RbConfig::CONFIG['host_os'] =~ /mswin/ ? 'nmake' : 'make')

# On Windows the compiler toolchain lives in RubyInstaller's bundled MSYS2 and isn't on PATH by default.
# This puts it there for the life of this process, which is what `ridk enable` does interactively and what
# `gem install` does when it says "Temporarily enhancing PATH for MSYS/MINGW". A no-op everywhere else.
def enable_toolchain
  return unless WINDOWS
  require 'ruby_installer/runtime'
  RubyInstaller::Runtime.enable_msys_apps
rescue LoadError
  warn "! Could not load RubyInstaller runtime; assuming make/gcc are already on PATH."
end

# Run a command, streaming its output, and abort the whole script if it fails, so we never carry on
# testing against a stale binary from a build that actually errored.
def run(*cmd, chdir: ROOT)
  puts "> #{cmd.join(' ')}"
  abort "! Command failed: #{cmd.join(' ')}" unless system(*cmd, chdir: chdir)
end

# Remove everything the build produces inside ext/: the linked binary, object files, and the generated
# Makefile. The final binary belongs in lib/, so none of this should linger in ext/ to be committed or packaged.
def sweep_ext
  Dir.glob(File.join(EXT_DIR, "*.{o,obj,so,bundle,dll,def,lib,exp,pdb,il?}")).each { |f| FileUtils.rm_f(f) }
  FileUtils.rm_f(File.join(EXT_DIR, 'Makefile'))
end

# Delete the compiled binary and every intermediate the build leaves behind, so each build starts clean
# and none of it gets committed or packaged by accident.
def clean
  FileUtils.rm_f(File.join(LIB_DIR, BINARY))
  sweep_ext
  puts "Cleaned build artifacts."
end

def build
  enable_toolchain
  clean                                               # Start from scratch: a stale Makefile can hide flag/source changes
  run(RbConfig.ruby, 'extconf.rb', chdir: EXT_DIR)    # (Re)generate the Makefile for this platform and Ruby
  run(MAKE, chdir: EXT_DIR)                            # Compile and link the extension
  FileUtils.mkdir_p(LIB_DIR)
  FileUtils.cp(File.join(EXT_DIR, BINARY), File.join(LIB_DIR, BINARY))
  sweep_ext                                           # Keep the copy in lib/ (the point); clear everything out of ext/
  puts "Built lib/#{BINARY}"
end

case ARGV[0]
when nil, 'build'
  build
when 'clean'
  clean
when 'test'
  build
  run(RbConfig.ruby, File.join('test', 'run.rb'))
when 'console'
  build
  # -I lib so `require 'ed2k'` resolves here rather than to any installed copy of the gem.
  exec(RbConfig.ruby, '-I', LIB_DIR, '-r', 'ed2k', '-r', 'irb', '-e', 'IRB.start')
else
  abort "Unknown command #{ARGV[0].inspect}. Use: build (default), test, console, or clean."
end
