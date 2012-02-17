package KSM::Daemon;

use warnings;
use strict;
use Carp;
use File::Basename ();
use POSIX ":sys_wait_h";
use KSM::Logger qw(debug verbose info warning error);

=head1 NAME

KSM::Daemon - The great new KSM::Daemon!

=head1 VERSION

Version 0.02

=cut

our $VERSION = '0.02';


=head1 SYNOPSIS

The KSM::Daemon module performs daemon management and assists with
logging for your perl programs.  It works in conjunction with
KSM::Logger.

Perhaps a little code snippet.

    use KSM::Logger qw(debug verbose info warning error);
    use KSM::Daemon;

    sub greeting {
        foreach (@_) {
	    print sprintf("Hello, %s!\n", $_);
        }
    }

    sub bar {
	print STDERR "bar\n";
    }

    KSM::Logger::initialize({filename_template => sprintf("%s/log/%s.%%F.%%s.log", 
						          POSIX::getcwd,
						          File::Basename::basename($0)),
			     level => KSM::Logger::DEBUG});

    KSM::Daemon::daemonize(
      [{name => "greeter",
        function => \&greeting,
        args => ["Abe", "Barry", "Charlie"],
        restart => 30,
        error => 60,
       },
       {name => "bar writer",
        function => \&bar,
        restart => 30,
        error => 60,
       }]);
    # NOTE: daemonize will not return unless invocation error
    exit(1);
    ...

=head1 EXPORT

Although nothing is exported by default, the most common functions may
be included by importing the :all tag.  For example:

    use KSM::Helper qw(:all);

=cut

use Exporter qw(import);
our %EXPORT_TAGS = ( 'all' => [qw(

)]);
our @EXPORT_OK = (@{$EXPORT_TAGS{'all'}});

=head1 GLOBALS

Some state is maintained by Monitor.

=cut

our $children = {};
our $unknown_children = {};
our $respawn = 1;
our $stdout_write;
our $stderr_write;

=head1 SUBROUTINES/METHODS

=head2 REAPER

Internal function to reap children processes once they have
terminated, and to spawn replacement processes in their place.

=cut

sub REAPER {
    my ($pid,$status,$child);
    # If a second child dies while in the signal handler caused by the
    # first death, we won't get another signal. So must loop here else
    # we will leave the unreaped child as a zombie. And the next time
    # two children die we get another zombie. And so on.
    while (($pid = waitpid(-1,WNOHANG)) > 0) {
	$status = $?;
	if(defined($child = $children->{$pid})) {
	    $child->{status} = $status;
	    $child->{ended} = POSIX::strftime("%s", gmtime);
	    $child->{duration} = ($child->{ended} - $child->{started});
	    if($child->{status}) {
		$child->{delay} = $child->{error_delay};
	    } else {
		$child->{delay} = $child->{restart_delay};
	    }
	    log_termination_of_child($child);
	    delete $children->{$pid};
            spawn_child($child) if $respawn;
	} else {
	    warn sprintf("reaped unknown child: %d", $pid);
	    # NOTE: this child's pid is left in $children, and
	    # relaying signals would attempt to send a non-child the
	    # signal.
	}
    }
    if(scalar(keys %$children)) {
	$SIG{CHLD} = \&REAPER;  # still loathe SysV
    } else {
	info("all children terminated: exiting.");
	exit;
    }
}

=head2 log_termination_of_child

Log the termination of a child process, including runtime statistics
and exit conditions.

=cut

sub log_termination_of_child {
    my ($child) = @_;

    if($child->{status}) {
	if($child->{status} & 127) {
	    warning('child %d (%s) received signal %d and terminated status code %d after %g seconds',
		    $child->{pid}, $child->{name},
		    $child->{status} & 127, $child->{status} >> 8, $child->{duration});
	} else {
	    warning('child %d (%s) terminated status code %d after %g seconds',
		    $child->{pid}, $child->{name},
		    $child->{status} >> 8, $child->{duration});
	}
    } else {
	info('child %d (%s) terminated status code 0 after %g seconds',
	     $child->{pid}, $child->{name}, $child->{status});
    }
    $child;
}

=head2 daemonize

nThis function daemonizes your program according to Perl best practices
in 'man perlipc', and spawns and monitors all the specified functions
in the argument list as a separate process.

It will respawn a child process that has terminated.  If the child
terminates without error, the child will be respawned after its
restart delay.  If the child terminates by error or otherwise, it will
respawn the child after the error delay.

=cut

sub daemonize {
    my ($requested_children) = @_;

    if(!defined($requested_children)
       || ref($requested_children) ne 'ARRAY'
       || scalar(@$requested_children) == 0) {
	croak sprintf("no children processes specified");
    }
 
    info("DAEMONIZING: %s", File::Basename::basename($0));
    daemonize_process();
    setup_signal_handlers();

    my ($stdout_read,$stderr_read);
    pipe($stdout_read, $stdout_write)
	or die error("unable to pipe: %s", $!);
    $stdout_write->autoflush(1);

    pipe($stderr_read, $stderr_write)
	or die error("unable to pipe: %s", $!);
    $stderr_write->autoflush(1);

    info("SPAWNING CHILDREN");
    foreach (@$requested_children) {
	spawn_child($_);
    }
    output_monitor($stdout_read,$stderr_read);
}

=head2 daemonize_process

Internal function that daemonizes the process, in accordance with
guidance in 'man perlipc'.

=cut

sub daemonize_process {
    chdir '/' or die sprintf('Cannot chdir(/): %s', $!);

    open STDIN,'/dev/null' or die sprintf('Cannot read from /dev/null: %s', $!);
    open STDOUT,'>/dev/null' or die sprintf('Cannot write to /dev/null: %s', $!);

    defined(my $pid = fork) or die sprintf('Cannot fork: %s', $!);
    exit if $pid;		# parent exits
    POSIX::setsid or die sprintf('Cannot start a new session: %s', $!);
    open STDERR,'>&STDOUT' or die sprintf('Cannot dup stdout: %s', $!);
}

=head2 setup_signal_handlers

Internal function that prepares signal handlers for USR1 and TERM
signals.

=cut

sub setup_signal_handlers {
    $SIG{CHLD} = \&REAPER;
    $SIG{INT} = \&terminate_program;
    $SIG{TERM} = \&terminate_program;
    # $SIG{USR1} = \&toggle_debug_mode;
}

=head2 terminate_program

Internal function that acts as the default handler for the TERM signal
to allow a program to perform a controlled exit.

When a TERM signal is received by the master process, Monitor will
send all children processes a TERM signal to allow them to exit, then
it will exit itself.  It does not wait for its children to exit.

=cut

sub terminate_program {
    my ($sig) = @_;
    $respawn = 0;
    info("received TERM/INT signal: preparing to shut down.");
    relay_signal_to_children('TERM');
}

=head2 relay_signal_to_children

Internal function used to relay a signal to children processes.

=cut

sub relay_signal_to_children {
    my ($sig) = @_;
    foreach my $pid (keys %$children) {
        info('relaying %s signal to child %d (%s)',
             $sig, $pid, $children->{$pid}->{name});
        kill($sig, $pid);
    }
}

=head2 spawn_child

Internal function that spawns a given child process, redirecting its
standard output and standard error to pipes monitored by the
&output_monitor function.

=cut

sub spawn_child {
    my ($child) = @_;

    my $signal_received;

    local $SIG{USR2} = sub { verbose("received USR2"); $signal_received = 1; $SIG{USR2} = 'DEFAULT'; };

    if(my $pid = fork) {
        # parent: TODO: look at foo.pl on penguin to remember how we
        # don't have race conditions if child executes before this
        # runs
        $children->{$pid} = $child;
	$child->{pid} = $pid;
	$child->{started} = POSIX::strftime("%s", gmtime);
        info('spawned child %d (%s) and signaling to continue', $pid, $child->{name});
	kill('USR2',$pid);
    } elsif(defined $pid) {
        $children = {};		# child has no children yet
        $0 = $child->{name};	# attempt to set name visible by ps(1)

	foreach (qw(CHLD INT TERM)) {$SIG{$_} = 'DEFAULT';}
	if(!$signal_received) {
	    verbose('sleeping until parent wakes me');
	    sleep; # until signal arrives
	}

        open(STDOUT, '>&=', $stdout_write)
            or die sprintf("cannot redirect STDOUT: %s\n", $!);
        open(STDERR, '>&=', $stderr_write)
            or die sprintf("cannot redirect STDERR: %s\n", $!);

        if(exists($child->{delay}) && $child->{delay}) {
            debug('snooze: %g seconds (%s)', $child->{delay}, $child->{name});
            sleep $child->{delay};
            delete $child->{delay};
        }

        # execute child code, and exit with appropriate status code
	eval { &{$child->{function}}(@{$child->{args}}) };
	if($@) {
	    exit 1;
	}
        exit($? >> 8);

    } else {
        die sprintf("unable to fork: %s", $!);
    }
}

=head2 output_monitor

Internal function that monitors two pipes, one for standard output and
one for standard input.  Data sent to standard output is redirected to
the log file in the form of an INFO message.  Data sent to standard
error is redirected to the log file in the form of an WARN message.

Because this uses the select(2) OS call to monitor two pipes, it must
use the Perl &sysread function to read from the pipe, as one cannot
mix buffered and unbuffered I/O.

=cut

sub output_monitor {
    my ($stdout_read,$stderr_read) = @_;

    info("MONITORING OUTPUT");

    my $rin = '';
    foreach ($stdout_read,$stderr_read) {
        vec($rin, fileno($_), 1) = 1;
    }
    my ($rout,$nfound,$output);
    while(1) {
        # http://perlmonks.org/?node=371720
        $nfound = select($rout=$rin, undef, undef, undef);
        next unless $nfound;

        if(vec($rout, fileno($stdout_read), 1) == 1) {
            $output = sysread_file_handle($stdout_read);
            foreach (split(/\n/, $output)) {
                info sprintf("child STDOUT: %s", $_);
            }
        }
        if(vec($rout, fileno($stderr_read), 1) == 1) {
            $output = sysread_file_handle($stderr_read);
            foreach (split(/\n/, $output)) {
                carp sprintf("child STDERR: %s", $_);
            }
        }
    }
}

=head2 sysread_file_handle

Internal function that reads from a given pipe using the OS read
function, strips any newline, and returns it to the calling function.

=cut

sub sysread_file_handle {
    my ($fh) = @_;
    my $output;
    sysread($fh, $output, 512);
    chomp($output);
    $output;
}

=head1 AUTHOR

Karrick S. McDermott, C<< <karrick at karrick.net> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-ksm-daemon at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=KSM-Daemon>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.




=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc KSM::Daemon


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=KSM-Daemon>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/KSM-Daemon>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/KSM-Daemon>

=item * Search CPAN

L<http://search.cpan.org/dist/KSM-Daemon/>

=back


=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

Copyright 2012 Karrick S. McDermott.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.


=cut

1; # End of KSM::Daemon
