use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'KSM::Daemon',
    AUTHOR              => q{Karrick S. McDermott <karrick@karrick.net>},
    VERSION_FROM        => 'lib/KSM/Daemon.pm',
    ABSTRACT_FROM       => 'lib/KSM/Daemon.pm',
    ($ExtUtils::MakeMaker::VERSION >= 6.3002
      ? ('LICENSE'=> 'perl')
      : ()),
    PL_FILES            => {},
    BUILD_REQUIRES => {
	'Test::Class' => 0,
        'Test::More' => 0,
    },
    PREREQ_PM => {
	# 'KSM::Logger' => 0,
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'KSM-Daemon-*' },
);

sub MY::postamble {
    my $postamble = <<'MAKE_FRAG';
.PHONY: rpm

rpm:	test dist
	cpan2rpm --no-sign $(DISTVNAME).tar.$(SUFFIX)
MAKE_FRAG

    return $postamble;
}
