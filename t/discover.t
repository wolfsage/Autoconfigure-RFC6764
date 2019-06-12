use lib qw(t/lib);
use lib qw(lib);

use strict;
use warnings;

use Test::More;
use Test::Deep ':v1';
use Test::Routine;
use Test::Routine::Util;

use Autoconfigure::RFC6764;
use Autoconfigure::RFC6764::MockDNSServer;

sub basic_mocker {
  Autoconfigure::RFC6764::MockDNSServer->basic_mocker(@_);
}

sub basic_mocked_autoconfigure {
  my ($ac_args, $mock_args) = @_;
  $ac_args ||= {};
  $mock_args ||= {};

  my $mock = basic_mocker($mock_args);
  my $server = $mock->as_server;
  my $ac = Autoconfigure::RFC6764->new({
    %$ac_args,
    resolver => $mock->resolver_for($server),
  });

  $ac->{_mock} = $mock;
  $ac->{_server} = $server;

  return $ac;
}

test "default settings - no txt records" => sub {
  my $ac = basic_mocked_autoconfigure;

  my $conf = $ac->discover('test@example.net');
  cmp_deeply(
    $conf,
    {
      caldav  => 'https://caldav.example.net/.well-known/caldav',
      carddav => 'https://carddav.example.net/.well-known/carddav',
    },
    "basic discover functionality looks good",
  ) or diag explain $conf;
};

test "default settings - txt records" => sub {
  my $ac = basic_mocked_autoconfigure({}, { include_txt => 1 });

  my $conf = $ac->discover('test@example.net');
  cmp_deeply(
    $conf,
    {
      caldav  => 'https://caldav.example.net/foocalsecure',
      carddav => 'https://carddav.example.net/foocardsecure',
    },
    "basic discover functionality looks good",
  ) or diag explain $conf;
};

test "caldav only - construction time" => sub {
  my $ac = basic_mocked_autoconfigure({ check_caldav => 0 });

  my $conf = $ac->discover('test@example.net');
  cmp_deeply(
    $conf,
    {
      carddav => 'https://carddav.example.net/.well-known/carddav',
    },
    "got expected response",
  ) or diag explain $conf;
};

test "carddav only - construction time" => sub {
  my $ac = basic_mocked_autoconfigure({ check_carddav => 0 });

  my $conf = $ac->discover('test@example.net');
  cmp_deeply(
    $conf,
    {
      caldav  => 'https://caldav.example.net/.well-known/caldav',
    },
    "got expected response",
  ) or diag explain $conf;
};

test "caldav only - override" => sub {
  my $ac = basic_mocked_autoconfigure;

  my $conf = $ac->discover('test@example.net', { check_caldav => 0 });
  cmp_deeply(
    $conf,
    {
      carddav => 'https://carddav.example.net/.well-known/carddav',
    },
    "got expected response",
  ) or diag explain $conf;
};

test "carddav only - override" => sub {
  my $ac = basic_mocked_autoconfigure;

  my $conf = $ac->discover('test@example.net', { check_carddav => 0 });

  cmp_deeply(
    $conf,
    {
      caldav  => 'https://caldav.example.net/.well-known/caldav',
    },
    "got expected response",
  ) or diag explain $conf;
};

run_me;
done_testing;
