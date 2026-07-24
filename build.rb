#!/usr/bin/env ruby
# frozen_string_literal: true

# Rebuild the native extension and, optionally, test the gem. Runs the same on Windows, Linux and macOS,
# so there's no need to remember a different incantation per machine.
#
#   ruby build.rb            Compile the extension and drop the fresh binary into lib/.
#   ruby build.rb test       ...then run the whole test suite.
#   ruby build.rb console    ...then open an IRB session with the gem already loaded (as ED2K).
#   ruby build.rb clean      Remove the compiled binary and all build leftovers, then stop.
#   ruby build.rb lsp        Just (re)write ext/.clangd so the editor can find ruby.h, then stop.
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
# `gem install` does when it says "Temporarily enhancing PATH for MSYS/MINGW". A no-op everywhere else, and
# idempotent so the several callers below don't each prepend the toolchain to PATH again.
def enable_toolchain
  return unless WINDOWS
  return if @toolchain_enabled
  @toolchain_enabled = true
  require 'ruby_installer/runtime'
  RubyInstaller::Runtime.enable_msys_apps
rescue LoadError
  warn "! Could not load RubyInstaller runtime; assuming make/gcc are already on PATH."
end

# Find an executable on PATH, cross-platform. Returns its full path, or nil if it isn't there.
def which(cmd)
  exts = WINDOWS ? ['.exe', '.cmd', ''] : ['']
  ENV['PATH'].to_s.split(File::PATH_SEPARATOR).each do |dir|
    exts.each do |ext|
      path = File.join(dir, cmd + ext)
      return path if File.file?(path) && File.executable?(path)
    end
  end
  nil
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

# The compile flags clangd needs to parse the extension the way the real build does. The Ruby headers go
# in as -isystem, not -I, so clangd resolves ruby.h and the rb_* API but doesn't lint Ruby's own headers,
# only our .c files.
def clangd_flags
  flags = ['-xc', '-isystem', RbConfig::CONFIG['rubyhdrdir'], '-isystem', RbConfig::CONFIG['rubyarchhdrdir']]
  return flags unless WINDOWS

  # clangd parses with its own bundled clang, which defaults to an MSVC target and so can't find the mingw
  # system headers (windows.h, strings.h, ...) that Ruby's headers pull in, and won't locate them itself
  # since the toolchain isn't on the editor's PATH. Point it at the mingw target and system include dir,
  # taken from the very gcc the build uses. gcc's own intrinsic dirs are left out on purpose: clang ships
  # equivalents, and adding gcc's makes its ia32intrin.h collide with clang's builtins.
  enable_toolchain
  gcc = which('gcc') or return flags
  target = begin
    IO.popen([gcc, '-dumpmachine'], err: File::NULL, &:read).to_s.strip
  rescue StandardError
    ''
  end
  flags << "--target=#{target}" unless target.empty?
  sysinc = File.join(File.dirname(File.dirname(gcc)), 'include').tr('\\', '/')
  flags += ['-isystem', sysinc] if File.directory?(sysinc)
  flags
end

# Point clangd (the language server behind VS Code's C diagnostics) at the headers this build uses, by
# writing an ext/.clangd config. The compiler finds them on its own, because mkmf bakes the include paths
# into the Makefile, but clangd parses the sources independently and otherwise can't find ruby.h, which
# cascades into a flood of bogus errors on VALUE and every rb_* symbol. The paths are specific to this OS
# and Ruby version, so the file is generated (and git-ignored) rather than committed, and refreshed on
# every build so it stays correct after a Ruby upgrade or a hop between Windows and Linux.
def write_clangd
  flags = clangd_flags
  File.write(File.join(EXT_DIR, '.clangd'), <<~YAML)
    # Generated by build.rb so clangd resolves ruby.h and the system headers it needs. Machine- and
    # Ruby-version-specific, hence git-ignored; regenerate with `ruby build.rb lsp`.
    CompileFlags:
      Add:
    #{flags.map { |f| "    - #{f}" }.join("\n")}
  YAML
  puts "Wrote ext/.clangd"
end

def build
  enable_toolchain
  write_clangd                                        # Keep the editor's view of the headers in sync with this Ruby
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
when 'lsp'
  write_clangd
when 'test'
  build
  run(RbConfig.ruby, File.join('test', 'run.rb'))
when 'console'
  build
  # -I lib so `require 'ed2k'` resolves here rather than to any installed copy of the gem.
  exec(RbConfig.ruby, '-I', LIB_DIR, '-r', 'ed2k', '-r', 'irb', '-e', 'IRB.start')
else
  abort "Unknown command #{ARGV[0].inspect}. Use: build (default), test, console, clean, or lsp."
end
