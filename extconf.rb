
require 'mkmf'

have_headers = true

%w{
  unistd.h errno.h
  sys/ptrace.h sys/types.h sys/user.h sys/wait.h
}.each{|h|
  have_headers = have_header(h)
  break unless have_headers
}

if have_headers
  create_makefile('ptrace')
end
