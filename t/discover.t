use lib qw(t/lib);
use lib qw(lib);

use strict;
use warnings;

use Test::More;
use Test::Deep;
use Test::Routine;
use Test::Routine::Util;

use Autoconfigure::RFC6764;
use Autoconfigure::RFC6764::MockDNSServer;

test "default settings" => sub {
  my $mock = Autoconfigure::RFC6764::MockDNSServer->basic_mocker;
  my $server = $mock->as_server;

  my $c = Autoconfigure::RFC6764->new({
    resolver => Net::DNS::Resolver->new(
      nameservers => [ '127.0.0.1' ],
      port        => $server->port,
    ),
  });

  my $conf = $c->discover('test@example.net');
  cmp_deeply(
    $conf,
    {
      caldav  => 'https://caldav.example.net/.well-known/caldav',
      carddav => 'https://carddav.example.net/.well-known/carddav',
    },
    "basic discover functionality looks good",
  );
};

test "caldav only - construction time" => sub {
  ok(1);
};

test "carddav only - construction time" => sub {
  ok(1);
};

test "caldav only - override" => sub {
  ok(1);
};

test "carddav only - override" => sub {
  ok(1);
};

run_me;
done_testing;
