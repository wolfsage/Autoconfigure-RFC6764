use strict;
use warnings;
package Autoconfigure::RFC6764;
#ABSTRACT: Service discovery for CalDav/CardDAV according to RFC 6764

use Carp;
use Moose;
use Net::DNS;
use IO::Select;

has resolver => (
  is => 'ro',
  isa => 'Net::DNS::Resolver',
  default => sub { Net::DNS::Resolver->new }
);

has timeout => (
  is => 'ro',
  isa => 'Int',
  default => sub { 5 },
);

has check_caldav => (
  is      => 'ro',
  isa     => 'Bool',
  default => 1,
);

has check_carddav => (
  is      => 'ro',
  isa     => 'Bool',
  default => 1,
);

sub discover {
  my ($self, $email, $overrides) = @_;

  my (undef, $domain) = split m/@/, $email;
  unless ($domain) {
    croak("Invalid email '$email'? No domain part detected");
  }

  $domain = lc $domain;

  my %to_lookup;

  my $check_caldav = exists $overrides->{check_caldav}
                       ? $overrides->{check_caldav}
                       : $self->check_caldav;

  my $check_carddav = exists $overrides->{check_carddav}
                       ? $overrides->{check_carddav}
                       : $self->check_carddav;

  unless ($check_caldav || $check_carddav) {
    croak("Need at least one of check_caldav or check_carddav!");
  }

  if ($check_caldav) {
    $to_lookup{"_caldavs._tcp.$domain"}{srv} = 1;
    $to_lookup{"_caldav._tcp.$domain"}{srv} = 1;
    $to_lookup{"_caldavs._tcp.$domain"}{txt} = 1;
    $to_lookup{"_caldav._tcp.$domain"}{txt} = 1;
  }

  if ($check_carddav) {
    $to_lookup{"_carddavs._tcp.$domain"}{srv} = 1;
    $to_lookup{"_carddav._tcp.$domain"}{srv} = 1;
    $to_lookup{"_carddavs._tcp.$domain"}{txt} = 1;
    $to_lookup{"_carddav._tcp.$domain"}{txt} = 1;
  }

  my $records = $self->lookup(\%to_lookup);

  my $srvs = $self->pick_srv_records($domain, $records);
  my $txts = $self->pick_txt_records($srvs, $records);

  my $urls = $self->records_to_urls($srvs, $txts);

  return $urls;
}

sub lookup {
  my ($self, $to_lookup) = @_;

  my $select = IO::Select->new;

  for my $host (sort keys %$to_lookup) {
    for my $type (sort keys %{ $to_lookup->{$host} }) {
      my $sock = $self->resolver->bgsend($host, $type);
      unless ($sock) {
        croak("Failed to bgsend: " . $self->resolver->errorstring);
      }
      $select->add($sock);
    }
  }

  my @records;

  my $start = time;

  while (time < $start + $self->timeout) {
    my @ready = $select->can_read(1);
    if (@ready) {
      for my $socket (@ready) {
        my $packet = $self->resolver->bgread($socket);
        push @records, $packet->answer;
        $select->remove($socket);
      }
    }
    last unless $select->count;
  }

  return \@records;
}

sub pick_srv_records {
  my ($self, $domain, $records) = @_;

  my %srvs;

  # Prefer secure over non
  for my $host ("_caldavs._tcp.$domain", "_caldav._tcp.$domain") {
    my ($pick) = sort _sort_srv grep {
      lc $_->type eq 'srv' && lc $_->owner eq $host
    } @$records;

    if ($pick) {
      $srvs{lc $pick->owner} = $pick;
      last;
    }
  }

  # Prefer secure over non
  for my $host ("_carddavs._tcp.$domain", "_carddav._tcp.$domain") {
    my ($pick) = sort _sort_srv grep {
      lc $_->type eq 'srv' && lc $_->owner eq $host
    } @$records;

    if ($pick) {
      $srvs{lc $pick->owner} = $pick;
      last;
    }
  }

  return \%srvs;
}

sub _sort_srv {
  # Low prio is the pick, otherwise highest weight if identical prio
  return $a->priority <=> $b->priority || $b->weight <=> $a->weight;
}

sub pick_txt_records {
  my ($self, $srvs, $records) = @_;

  my %txts;

  for my $host (keys %$srvs) {
    my ($pick) = grep {
      lc $_->type eq 'txt' && lc $_->owner eq lc $host
    } @$records;

    $txts{$host} = $pick if $pick;
  }

  return \%txts;
}

sub records_to_urls {
  my ($self, $srvs, $txts) = @_;

  my %urls;

  for my $srvhost (keys %$srvs) {
    my $srv = $srvs->{$srvhost};
    my $txt = $txts->{$srvhost};

    my $secure = $srvhost =~ /^_(?:caldav|carddav)s\./ ? 1 : 0;
    my $davtype = $srvhost =~ /^_caldav/ ? 'caldav' : 'carddav';
    my $protocol = $secure ? 'https' : 'http';

    my $host = $srv->target;
    my $port = $srv->port;

    # Don't add in well-known ports
    my $port_part;

    if ($port == 80 && ! $secure) {
      $port_part = "";
    } elsif ($port == 443 && $secure) {
      $port_part = "";
    } else {
      $port_part = ":$port";
    }

    my $path_part;

    if ($txt) {
      my ($path) = grep { /^path=/ } map { lc } $txt->txtdata;
      if ($path) {
        $path =~ s/^path=//;
        $path = "/$path" unless $path =~ m{^/};
        $path_part = $path;
      }
    }

    $path_part ||= "/.well-known/$davtype";

    $urls{$davtype} = "$protocol://$host$port_part$path_part";
  }

  return \%urls;
}

1;
