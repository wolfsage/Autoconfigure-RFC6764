package Autoconfigure::RFC6764::MockDNSServer;

use Moose;
use MooseX::StrictConstructor;

use namespace::autoclean;

use Carp qw(croak);
use Storable qw(dclone);
use Try::Tiny;
use Test::TCP 2.15;
use Net::DNS;

has matchers => (
  is => 'ro',
  isa => 'HashRef',
  default => sub { {} },
);

has sleep_after_seconds => (
  is => 'ro',
  isa => 'Int',
  default => 0,
);

sub reset {
  shift->{matchers} = {};
}

sub resolver_for {
  my ($self, $server) = @_;

  return Net::DNS::Resolver->new(
    nameservers => [ '127.0.0.1' ],
    port        => $server->port,
  );
}

sub as_server {
  my ($self) = @_;

  my $sleep = $self->sleep_after_seconds;

  return Test::TCP->new(
    listen => 1,
    proto  => 'udp',
    code => sub {
      my $socket = shift;
      while (1) {
        $socket->recv(my $data, 65535);
        my $packet = Net::DNS::Packet->new(\$data);
        $socket->send($self->query_handler($packet));
        sleep $sleep if $sleep;
      }
    }
  );
}

sub add {
  my ($self, $args) = @_;
  my $host = delete($args->{host}) // croak("host required");
  my $type = delete($args->{type}) // croak("type required");
  my $class = delete($args->{class}) // "IN";

  my $rr = try {
    Net::DNS::RR->new(
      name => $host,
      type => $type,
      %$args
    );
  } catch {
    croak("Failed to create a Net::DNS::RR object: $_");
  };

  push @{ $self->matchers->{lc $host}{lc $class}{lc $type} }, $rr;

  return $rr;
}

sub query_handler {
  my ($self, $query_packet) = @_;

  my ($question) = $query_packet->question;

  my $host = $question->qname;
  my $type = $question->qtype;
  my $class = $question->qclass;

  my $rrs = $self->matchers->{lc $host}{lc $class}{lc $type} || [];
  my $packet = $query_packet->reply;

  $packet->push(answer => dclone($_)) for @$rrs;

  return $packet->data;
}

sub basic_mocker {
  my ($class, $opt) = @_;

  my $sleep = delete $opt->{sleep_after_seconds};

  my $mock = __PACKAGE__->new({
    sleep_after_seconds => $sleep // 0,
  });

  my $alt = $opt->{alt_ports};

  unless ($opt->{no_secure}) {
    $mock->add({
      host     => '_caldavs._tcp.example.net',
      type     => 'srv',
      priority => 1,
      weight   => 1,
      target   => 'caldav.example.net',
      port     => $alt ? 9443 : 443,
    });
  }

  $mock->add({
    host     => '_caldav._tcp.example.net',
    type     => 'srv',
    priority => 1,
    weight   => 1,
    target   => 'caldav.example.net',
    port     => $alt ? 8080 : 80,
  });

  unless ($opt->{no_secure}) {
    $mock->add({
      host     => '_carddavs._tcp.example.net',
      type     => 'srv',
      priority => 1,
      weight   => 1,
      target   => 'carddav.example.net',
      port     => $alt ? 9444 : 443,
    });
  }

  $mock->add({
    host     => '_carddav._tcp.example.net',
    type     => 'srv',
    priority => 1,
    weight   => 1,
    target   => 'carddav.example.net',
    port     => $alt ? 8081 : 80,
  });

  if ($opt->{include_txt}) {
    unless ($opt->{no_secure}) {
      $mock->add({
        host     => '_caldavs._tcp.example.net',
        type     => 'txt',
        txtdata  => [ "txtversion=1", "path=/foocalsecure" ],
      });
    }

    $mock->add({
      host     => '_caldav._tcp.example.net',
      type     => 'txt',
      txtdata  => [ "txtversion=1", "path=/foocal" ],
    });

    unless ($opt->{no_secure}) {
      $mock->add({
        host     => '_carddavs._tcp.example.net',
        type     => 'txt',
        txtdata  => [ "txtversion=1", "path=/foocardsecure" ],
      });
    }

    $mock->add({
      host     => '_carddav._tcp.example.net',
      type     => 'txt',
      txtdata  => [ "txtversion=1", "path=/foocard" ],
    });
  }

  return $mock;
}

1;
