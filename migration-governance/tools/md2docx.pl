#!/usr/bin/perl
# Markdown -> Word (.docx) for the migration governance guides.
# Graphics are drawn natively in Word: banners, phase strips, the SQL x Windows matrix,
# Mermaid flowcharts / gantt / gitGraph, callouts and code blocks.
#
# Usage: perl tools/md2docx.pl <out.docx> <guide.md> [<guide.md> ...]
#        (run from migration-governance/; several guides make one combined document with a TOC)
use strict;
use warnings;
use utf8;
use IO::Compress::Zip qw($ZipError);
use File::Basename qw(dirname basename);
use Time::Local qw(timegm);
use POSIX qw(strftime);

my ($OUT, @MD) = @ARGV;
die "usage: $0 out.docx file.md [...]\n" unless $OUT && @MD;

my $NAVY  = '1B4A78';
my $DEEP  = '12365A';
my $SKY   = '5FA8E8';
my $LIGHT = 'DBE8F4';
my $GREY  = 'EEF1F4';
my $LINE  = 'A9C6E2';
my $TEXT  = '1F2A36';
my $MUTED = '6B7785';
my $FONT  = 'Segoe UI';
my $MONO  = 'Consolas';
my $TEXT_W = 12240 - 2 * 1080;    # Letter, 0.75" margins

my %CALLOUT = (    # label, accent, fill
    NOTE      => ['Note',      '0969DA', 'DDF4FF'],
    TIP       => ['Tip',       '1A7F37', 'DAFBE1'],
    IMPORTANT => ['Important', '8250DF', 'FBEFFF'],
    WARNING   => ['Warning',   '9A6700', 'FFF8C5'],
    CAUTION   => ['Caution',   'CF222E', 'FFEBE9'],
);

# ---------------------------------------------------------------- numbering
my @NUMS;    # list of [numId, abstractId]
sub new_num { my $abs = shift; my $id = @NUMS + 1; push @NUMS, [$id, $abs]; return $id }
my $BULLET = new_num(0);

# ---------------------------------------------------------------- inline
sub esc {
    my $s = shift;
    $s =~ s/&/&amp;/g; $s =~ s/</&lt;/g; $s =~ s/>/&gt;/g; $s =~ s/"/&quot;/g;
    return $s;
}

sub decode_entities {
    my $s = shift;
    $s =~ s/&nbsp;/ /g; $s =~ s/&middot;/\x{b7}/g; $s =~ s/&lt;/</g; $s =~ s/&gt;/>/g;
    $s =~ s/&quot;/"/g; $s =~ s/&amp;/&/g;
    return $s;
}

sub run {
    my ($text, %f) = @_;
    return '' if !defined $text || $text eq '';
    my $r = '';
    $r .= "<w:rFonts w:ascii=\"$MONO\" w:hAnsi=\"$MONO\" w:cs=\"$MONO\"/>" if $f{code};
    $r .= '<w:b/>' if $f{b};
    $r .= '<w:i/>' if $f{i};
    $r .= '<w:caps/>' if $f{caps};
    my $color = $f{color} // ($f{link} ? $NAVY : $f{code} ? 'A0303B' : undef);
    $r .= "<w:color w:val=\"$color\"/>" if $color;
    $r .= "<w:spacing w:val=\"$f{spacing}\"/>" if $f{spacing};
    my $sz = $f{sz} // ($f{small} ? 16 : undef);
    $r .= "<w:sz w:val=\"$sz\"/><w:szCs w:val=\"$sz\"/>" if $sz;
    $r .= '<w:u w:val="single"/>' if $f{link};
    $r .= '<w:shd w:val="clear" w:color="auto" w:fill="F3F4F6"/>' if $f{code} && !$f{nocodeshade};
    my @parts = split /\n/, $text, -1;
    my $xml = '';
    for my $i (0 .. $#parts) {
        $xml .= "<w:r><w:rPr>$r</w:rPr><w:br/></w:r>" if $i > 0;
        $xml .= "<w:r><w:rPr>$r</w:rPr><w:t xml:space=\"preserve\">" . esc($parts[$i]) . '</w:t></w:r>' if $parts[$i] ne '';
    }
    return $xml;
}

sub inline {
    my ($s, %f) = @_;
    my $xml = '';
    while (length $s) {
        if    ($s =~ s/^<br\s*\/?>//i)                          { $xml .= '<w:r><w:br/></w:r>' }
        elsif ($s =~ s/^<(b|strong)>(.*?)<\/\1>//is)            { $xml .= inline($2, %f, b => 1) }
        elsif ($s =~ s/^<sub>(.*?)<\/sub>//is)                  { $xml .= inline($1, %f, small => 1, color => $f{color} // $MUTED) }
        elsif ($s =~ s/^<code>(.*?)<\/code>//is)                { $xml .= run(decode_entities($1), %f, code => 1) }
        elsif ($s =~ s/^<a\s[^>]*>(.*?)<\/a>//is)               { $xml .= inline($1, %f, link => 1) }
        elsif ($s =~ s/^<\/?[a-z][^>]*>//i)                     { }
        elsif ($s =~ s/^`([^`]+)`//)                            { $xml .= run(decode_entities($1), %f, code => 1) }
        elsif ($s =~ s/^\*\*\*(.+?)\*\*\*//)                    { $xml .= inline($1, %f, b => 1, i => 1) }
        elsif ($s =~ s/^\*\*(.+?)\*\*//)                        { $xml .= inline($1, %f, b => 1) }
        elsif ($s =~ s/^\*([^*\s][^*]*?)\*//)                   { $xml .= inline($1, %f, i => 1) }
        elsif ($s =~ s/^\[([^\]]+)\]\(([^)]+)\)//)              { $xml .= inline($1, %f, link => 1) }
        elsif ($s =~ s/^([^`*\[<]+)//)                          { $xml .= run(decode_entities($1), %f) }
        else  { $s =~ s/^(.)//s; $xml .= run(decode_entities($1), %f) }
    }
    return $xml;
}

sub plain {
    my $s = shift;
    $s =~ s/<br\s*\/?>/ /gi; $s =~ s/<[^>]+>//g; $s =~ s/\[([^\]]+)\]\([^)]+\)/$1/g; $s =~ s/[`*]//g;
    return decode_entities($s);
}

# ---------------------------------------------------------------- blocks
sub para {
    my ($runs, %p) = @_;
    my $ppr = '';
    $ppr .= "<w:pStyle w:val=\"$p{style}\"/>" if $p{style};
    $ppr .= '<w:keepNext/>' if $p{keep};
    $ppr .= '<w:pageBreakBefore/>' if $p{pagebreak};
    $ppr .= "<w:numPr><w:ilvl w:val=\"" . ($p{lvl} // 0) . "\"/><w:numId w:val=\"$p{num}\"/></w:numPr>" if $p{num};
    $ppr .= $p{bdr} if $p{bdr};
    $ppr .= "<w:shd w:val=\"clear\" w:color=\"auto\" w:fill=\"$p{fill}\"/>" if $p{fill};
    $ppr .= "<w:spacing w:before=\"" . ($p{before} // 0) . "\" w:after=\"" . ($p{after} // 0) . "\"/>" if defined $p{before} || defined $p{after};
    $ppr .= "<w:ind w:left=\"$p{ind}\"/>" if $p{ind};
    $ppr .= "<w:jc w:val=\"$p{jc}\"/>" if $p{jc};
    $ppr .= "<w:outlineLvl w:val=\"$p{outline}\"/>" if defined $p{outline};
    return "<w:p><w:pPr>$ppr</w:pPr>$runs</w:p>";
}

sub border { my ($side, $color, $sz) = @_; return "<w:$side w:val=\"single\" w:sz=\"$sz\" w:space=\"0\" w:color=\"$color\"/>" }

sub tc {
    my ($content, $w, %c) = @_;
    my $pr = "<w:tcW w:w=\"$w\" w:type=\"dxa\"/>";
    $pr .= "<w:gridSpan w:val=\"$c{span}\"/>" if $c{span} && $c{span} > 1;
    if ($c{borders}) { $pr .= "<w:tcBorders>$c{borders}</w:tcBorders>" }
    $pr .= "<w:shd w:val=\"clear\" w:color=\"auto\" w:fill=\"$c{fill}\"/>" if $c{fill};
    $pr .= "<w:tcMar>$c{mar}</w:tcMar>" if $c{mar};
    $pr .= '<w:vAlign w:val="' . ($c{valign} // 'top') . '"/>';
    $content = para('', style => 'TableText') if $content !~ /<w:p>/;
    return "<w:tc><w:tcPr>$pr</w:tcPr>$content</w:tc>";
}

sub tbl {
    my ($rows_xml, $widths, %t) = @_;
    my $total = 0; $total += $_ for @$widths;
    my $b = $t{noborders} ? '' : join '', map { border($_, $t{bcolor} // $LINE, 4) } qw(top left bottom right insideH insideV);
    my $bx = $t{noborders}
        ? '<w:tblBorders>' . join('', map { "<w:$_ w:val=\"nil\"/>" } qw(top left bottom right insideH insideV)) . '</w:tblBorders>'
        : "<w:tblBorders>$b</w:tblBorders>";
    my $mar = $t{mar} // '<w:top w:w="60" w:type="dxa"/><w:left w:w="100" w:type="dxa"/><w:bottom w:w="60" w:type="dxa"/><w:right w:w="100" w:type="dxa"/>';
    my $jc = $t{jc} ? "<w:jc w:val=\"$t{jc}\"/>" : '';
    return "<w:tbl><w:tblPr><w:tblW w:w=\"$total\" w:type=\"dxa\"/>$jc$bx<w:tblLayout w:type=\"fixed\"/><w:tblCellMar>$mar</w:tblCellMar></w:tblPr>"
         . '<w:tblGrid>' . join('', map { "<w:gridCol w:w=\"$_\"/>" } @$widths) . '</w:tblGrid>'
         . $rows_xml . '</w:tbl>' . para('', style => 'Spacer');
}

sub row { my ($cells, %r) = @_; my $pr = ''; $pr .= '<w:cantSplit/>' if $r{cantsplit}; $pr .= '<w:tblHeader/>' if $r{header}; return "<w:tr>" . ($pr ? "<w:trPr>$pr</w:trPr>" : '') . "$cells</w:tr>" }

sub split_widths {
    my ($n, @weights) = @_;
    @weights = (1) x $n unless @weights;
    my $sum = 0; $sum += $_ for @weights;
    my @w = map { int($TEXT_W * $_ / $sum) } @weights;
    my $t = 0; $t += $_ for @w; $w[-1] += $TEXT_W - $t;
    return @w;
}

# Lines of markdown inside a cell or callout -> paragraphs
sub mini_blocks {
    my ($text, %o) = @_;
    my $xml = '';
    my $num;
    my $style = $o{style} // 'TableText';
    for my $l (split /\n/, $text) {
        next if $l =~ /^\s*$/;
        my $lvl = ($l =~ /^(\s+)/ && length($1) >= 2) ? 1 : 0;
        $l =~ s/^\s+//;
        if ($l =~ /^- \[[ xX]\]\s+(.*)/) {
            $xml .= para(run("\x{2610}  ", color => $NAVY) . inline($1, %{ $o{f} // {} }), style => $style, ind => 200 + $lvl * 300);
            undef $num;
        } elsif ($l =~ /^[-*]\s+(.*)/) {
            $xml .= para(inline($1, %{ $o{f} // {} }), style => $style, num => $BULLET, lvl => $lvl);
            undef $num;
        } elsif ($l =~ /^\d+\.\s+(.*)/) {
            $num //= new_num(1);
            $xml .= para(inline($1, %{ $o{f} // {} }), style => $style, num => $num);
        } else {
            $xml .= para(inline($l, %{ $o{f} // {} }), style => $style, jc => $o{jc});
            undef $num;
        }
    }
    return $xml || para('', style => $style);
}

sub pipe_table {
    my @lines = @_;
    my @rows = map {
        my $r = $_; $r =~ s/^\s*\|//; $r =~ s/\|\s*$//;
        [ map { my $c = $_; $c =~ s/^\s+|\s+$//g; $c } split /(?<!\\)\|/, $r, -1 ]
    } @lines;
    my $header = shift @rows;
    shift @rows if @rows && $rows[0][0] =~ /^:?-+:?$/;
    my $n = @$header;
    my $kv = !grep { $_ ne '' } @$header;
    my @len = map { my $i = $_; my $m = length plain($header->[$i]);
        for my $r (@rows) { my $l = length plain($r->[$i] // ''); $m = $l if $l > $m } $m < 5 ? 5 : $m > 70 ? 70 : $m } 0 .. $n - 1;
    @len = (28, 72) if $kv && $n == 2;
    my @w = split_widths($n, @len);
    my $xml = '';
    unless ($kv) {
        $xml .= row(join('', map { tc(para(inline($header->[$_], b => 1, color => 'FFFFFF'), style => 'TableText'), $w[$_], fill => $NAVY) } 0 .. $n - 1), header => 1);
    }
    for my $r (@rows) {
        my $section = $r->[0] =~ /^\*\*\*.*\*\*\*$/ && !grep { ($r->[$_] // '') ne '' } 1 .. $n - 1;
        if ($section) {
            $xml .= row(tc(para(inline($r->[0], color => $NAVY), style => 'TableText'), $TEXT_W, span => $n, fill => $LIGHT));
            next;
        }
        $xml .= row(join('', map {
            my %c = ($kv && $_ == 0) ? (fill => $LIGHT) : ();
            tc(para(inline($r->[$_] // '', ($kv && $_ == 0) ? (b => 1) : ()), style => 'TableText'), $w[$_], %c)
        } 0 .. $n - 1), cantsplit => 1);
    }
    return tbl($xml, \@w);
}

sub html_table {
    my $html = shift;
    my @rows;
    while ($html =~ /<tr[^>]*>(.*?)<\/tr>/gis) {
        my $r = $1; my @cells;
        while ($r =~ /<(th|td)([^>]*)>(.*?)<\/\1>/gis) {
            my ($tag, $attr, $c) = ($1, $2, $3);
            my ($span) = $attr =~ /colspan="(\d+)"/; my ($wp) = $attr =~ /width="(\d+)%"/; my ($al) = $attr =~ /align="(\w+)"/;
            push @cells, { th => lc $tag eq 'th', span => $span // 1, w => $wp, align => $al, c => $c };
        }
        push @rows, \@cells if @cells;
    }
    return '' unless @rows;
    my ($wide) = sort { (sum_span($b)) <=> (sum_span($a)) } @rows;
    my $n = sum_span($wide);
    my @weights = map { $_->{w} // 0 } @$wide;
    @weights = () if grep { !$_ } @weights or @$wide != $n;
    my @w = split_widths($n, @weights);
    my $xml = '';
    for my $r (@rows) {
        my $col = 0; my $cells = '';
        for my $c (@$r) {
            my $cw = 0; $cw += $w[$_] for $col .. $col + $c->{span} - 1; $col += $c->{span};
            my $content = $c->{c}; $content =~ s/^\s+|\s+$//g;
            my $inner = $c->{th}
                ? para(inline($content, b => 1, color => 'FFFFFF'), style => 'TableText')
                : mini_blocks($content, jc => ($c->{align} // '') eq 'center' ? 'center' : undef);
            $cells .= tc($inner, $cw, span => $c->{span}, fill => $c->{th} ? $NAVY : undef);
        }
        $xml .= row($cells, cantsplit => 1);
    }
    return tbl($xml, \@w);
}
sub sum_span { my $r = shift; my $s = 0; $s += $_->{span} for @$r; return $s }

sub code_block {
    my @lines = @_;
    my $p = '';
    for my $l (@lines) { $p .= para(run($l eq '' ? ' ' : $l, code => 1, nocodeshade => 1, sz => 17, color => '24292F'), style => 'Code') }
    return tbl(row(tc($p, $TEXT_W, fill => 'F6F8FA')), [$TEXT_W], bcolor => 'D0D7DE');
}

sub callout {
    my ($type, $text) = @_;
    my ($label, $accent, $fill) = @{ $CALLOUT{$type} // $CALLOUT{NOTE} };
    my $inner = para(run($label, b => 1, color => $accent, caps => 1, spacing => 20, sz => 17), style => 'TableText', after => 40) . mini_blocks($text);
    my $b = border('top', $fill, 4) . border('left', $accent, 24) . border('bottom', $fill, 4) . border('right', $fill, 4);
    return tbl(row(tc($inner, $TEXT_W, fill => $fill, borders => $b)), [$TEXT_W], noborders => 1,
               mar => '<w:top w:w="100" w:type="dxa"/><w:left w:w="200" w:type="dxa"/><w:bottom w:w="100" w:type="dxa"/><w:right w:w="200" w:type="dxa"/>');
}

# ---------------------------------------------------------------- graphics
sub svg_texts {
    my $file = shift;
    open my $fh, '<:encoding(UTF-8)', $file or return ();
    local $/; my $svg = <$fh>; close $fh;
    my @t = $svg =~ /<text[^>]*>([^<]*)<\/text>/g;
    return map { decode_entities($_) } @t;
}

sub banner {
    my ($eyebrow, $title, $subtitle, @phases) = @_;
    my $c = para(run($eyebrow, b => 1, color => '8FC1EE', sz => 16, spacing => 40), style => 'TableText', after => 120)
          . para(run($title, b => 1, color => 'FFFFFF', sz => 56), style => 'Heading1', outline => 0, after => 60,
                 bdr => '<w:pBdr>' . border('bottom', $SKY, 12) . '</w:pBdr>')
          . para(run($subtitle, color => 'D6E6F5', sz => 24), style => 'TableText', before => 120, after => 160);
    if (@phases) {
        $c .= para(join(run("   \x{2014}   ", color => $SKY, sz => 16),
                        map { run("\x{25CF} ", color => $SKY, sz => 16) . run($_, b => 1, color => 'FFFFFF', sz => 16, spacing => 20) } @phases),
                   style => 'TableText', after => 40);
    }
    return tbl(row(tc($c, $TEXT_W, fill => $DEEP)), [$TEXT_W], noborders => 1,
               mar => '<w:top w:w="360" w:type="dxa"/><w:left w:w="420" w:type="dxa"/><w:bottom w:w="300" w:type="dxa"/><w:right w:w="420" w:type="dxa"/>');
}

sub phase_strip {
    my $active = shift;
    my @names = ('Discovery', 'Install & configure', 'Migration', 'Decommissioning');
    my @w = split_widths(4);
    my $cells = '';
    for my $i (1 .. 4) {
        my ($fill, $t1, $t2) = $i == $active ? ($NAVY, '8FC1EE', 'FFFFFF') : $i < $active ? ($LIGHT, $NAVY, $NAVY) : ($GREY, '8A96A3', $MUTED);
        my $c = para(run("PHASE $i", b => 1, color => $t1, sz => 15, spacing => 40), style => 'TableText')
              . para(run($names[$i - 1], b => 1, color => $t2, sz => 20), style => 'TableText');
        my $b = border('left', 'FFFFFF', 18) . border('right', 'FFFFFF', 18);
        $cells .= tc($c, $w[$i - 1], fill => $fill, borders => $b);
    }
    return tbl(row($cells, cantsplit => 1), \@w, noborders => 1,
               mar => '<w:top w:w="100" w:type="dxa"/><w:left w:w="160" w:type="dxa"/><w:bottom w:w="100" w:type="dxa"/><w:right w:w="160" w:type="dxa"/>');
}

sub divider {
    return para(run("\x{2014}\x{2014}\x{2014}   \x{25C6}   \x{2014}\x{2014}\x{2014}", color => $SKY, sz => 18), jc => 'center', before => 160, after => 160);
}

sub matrix {
    my @os = ('2003', '2008', '2008 R2', '2012', '2012 R2', '2016', '2019', '2022', '2025');
    my @rows = (
        ['SQL 2000',    qw(S:SP3 U U U U U U U U)],
        ['SQL 2005',    qw(S:RTM S:SP2 S:SP3 U L U U U L)],
        ['SQL 2008',    qw(S:RTM S:RTM S:SP1 S:SP4 S:SP4 U U U U)],
        ['SQL 2008 R2', qw(S:RTM S:RTM S:RTM S:SP3 S:SP3 U U U U)],
        ['SQL 2012',    qw(X S:RTM S:RTM S:SP4 S:SP4 S:SP4 S:SP4 U U)],
        ['SQL 2014',    qw(X S:RTM S:RTM S:SP3 S:SP3 S:SP3 S:SP3 U U)],
        ['SQL 2016',    qw(X X X S:SP3 S:SP3 S:SP3 S:SP3 U U)],
        ['SQL 2017',    qw(X X X S:RTM S:RTM S:RTM S:RTM S:RTM U)],
        ['SQL 2019',    qw(X X X X X S:RTM S:RTM S:RTM S:RTM)],
        ['SQL 2022',    qw(X X X X X S:RTM S:RTM S:RTM S:RTM)],
        ['SQL 2025',    qw(X X X X X X S:RTM S:RTM S:RTM)],
    );
    my %st = (S => [$NAVY, 'FFFFFF'], L => ['2F7D5B', 'FFFFFF'], U => [$GREY, $MUTED], X => ['FFFFFF', 'A0A9B3']);
    my @w = (1290, (976) x 9); $w[-1] += $TEXT_W - (1290 + 976 * 9);
    my $xml = row(tc(para(run('SQL \\ Windows', b => 1, color => 'FFFFFF', sz => 16), style => 'TableText'), $w[0], fill => $DEEP)
        . join('', map { tc(para(run($os[$_], b => 1, color => 'FFFFFF', sz => 18), style => 'TableText', jc => 'center'), $w[$_ + 1], fill => $DEEP) } 0 .. 8), header => 1);
    for my $r (@rows) {
        my ($name, @c) = @$r;
        my $cells = tc(para(run($name, b => 1, color => $NAVY, sz => 18), style => 'TableText'), $w[0], fill => $LIGHT);
        for my $i (0 .. 8) {
            my ($k, $v) = split /:/, $c[$i];
            my ($fill, $fg) = @{ $st{$k} };
            my $label = $k eq 'S' ? "Yes \x{b7} $v" : $k eq 'L' ? 'LAB OK' : $k eq 'U' ? 'unsupported' : 'not possible';
            $cells .= tc(para(run($label, b => ($k eq 'S' || $k eq 'L'), color => $fg, sz => ($k eq 'S' || $k eq 'L') ? 16 : 14), style => 'TableText', jc => 'center'),
                         $w[$i + 1], fill => $fill, valign => 'center');
        }
        $xml .= row($cells, cantsplit => 1);
    }
    my $legend = '';
    my @lg = (['S', 'Supported by Microsoft (minimum SQL service pack)'], ['L', 'Unsupported, proven in our lab'],
              ['U', 'Unsupported, not tested'], ['X', 'Not possible (setup requires a newer OS)']);
    my @lw = (400, 4640, 400, 4640);
    my $lrow = '';
    for my $i (0 .. 3) {
        my ($k, $t) = @{ $lg[$i] };
        $lrow .= tc(para('', style => 'TableText'), 400, fill => $st{$k}[0], borders => join('', map { border($_, $LINE, 4) } qw(top left bottom right)))
               . tc(para(run($t, sz => 16), style => 'TableText'), 4640);
        if ($i % 2) { $legend .= row($lrow); $lrow = '' }
    }
    return tbl($xml, \@w, bcolor => 'FFFFFF') . tbl($legend, \@lw, noborders => 1);
}

# ---- mermaid
sub mermaid {
    my @lines = @_;
    my $kind = '';
    for (@lines) { next if /^\s*(%%|$)/; ($kind) = /^\s*(\w+)/; last }
    return gantt(@lines) if $kind eq 'gantt';
    return gitgraph(@lines) if $kind eq 'gitGraph';
    return flowchart(@lines);
}

sub flowchart {
    my @lines = @_;
    my (%label, @order, @edges, %classdef, %class);
    my $node_re = qr/([A-Za-z][\w]*)\s*(\[\("(?:[^"]*)"\)\]|\(\["(?:[^"]*)"\]\)|\{\{"(?:[^"]*)"\}\}|\{"(?:[^"]*)"\}|\["(?:[^"]*)"\]|\("(?:[^"]*)"\))?/;
    my $edge_re = qr/\s*(?:(--|-\.|==)\s*"([^"]*)"\s*(-->|\.->|==>|\.-|---)|(-->|==>|-\.->|-\.-|---))\s*/;
    for my $l (@lines) {
        next if $l =~ /^\s*(flowchart|graph)\b/ || $l =~ /^\s*%%/ || $l =~ /^\s*$/;
        if ($l =~ /^\s*classDef\s+(\w+)\s+(.*)/) {
            my ($n, $d) = ($1, $2); my %d = map { split /:/, $_, 2 } split /,/, $d;
            $classdef{$n} = { fill => ($d{fill} // '') =~ s/#//r, color => ($d{color} // '') =~ s/#//r };
            next;
        }
        if ($l =~ /^\s*class\s+([\w,]+)\s+(\w+)/) { $class{$_} = $2 for split /,/, $1; next }
        my $s = $l; my $prev; my $pending;
        while (length $s) {
            $s =~ s/^\s+//;
            last unless length $s;
            if ($s =~ s/^$node_re//) {
                my ($id, $shape) = ($1, $2);
                if ($shape && !exists $label{$id}) { my ($t) = $shape =~ /"([^"]*)"/; $label{$id} = $t }
                push @order, $id unless grep { $_ eq $id } @order;
                push @edges, [$prev, $id, @$pending] if defined $prev && $pending;
                $prev = $id; undef $pending;
            } elsif ($s =~ s/^$edge_re//) {
                my ($lab, $arrow) = defined $1 ? ($2, $3) : ('', $4);
                my $style = $arrow =~ /\./ || ($1 // '') eq '-.' ? 'dotted' : $arrow =~ /=/ ? 'thick' : 'solid';
                $pending = [$lab, $style];
            } else { last }
        }
    }
    $label{$_} //= $_ for @order;
    my %out; my %in;
    for my $e (@edges) { push @{ $out{$e->[0]} }, $e; $in{$e->[1]}++ }
    my $box = sub {
        my ($id, $w) = @_;
        my $cd = $classdef{ $class{$id} // '' } // {};
        my $fill = $cd->{fill} || $LIGHT; my $fg = $cd->{color} || '0B1F36';
        $fill = uc $fill; $fg = uc $fg;
        $fill = join '', map { $_ x 2 } split //, $fill if length $fill == 3;
        $fg = join '', map { $_ x 2 } split //, $fg if length $fg == 3;
        return tc(para(inline($label{$id}, color => $fg, sz => 17), style => 'TableText', jc => 'center'), $w, fill => $fill, valign => 'center',
                  borders => join('', map { border($_, 'FFFFFF', 12) } qw(top left bottom right)));
    };
    # Linear chain?
    my @starts = grep { !$in{$_} } @order;
    my $linear = @edges == @order - 1 && @starts == 1 && !grep { ($in{$_} // 0) > 1 || @{ $out{$_} // [] } > 1 } @order;
    if ($linear) {
        my @chain = ($starts[0]);
        push @chain, $out{ $chain[-1] }[0][1] while $out{ $chain[-1] };
        my $xml = '';
        my $per = 5;
        for (my $k = 0; $k < @chain; $k += $per) {
            my @seg = @chain[$k .. ($k + $per - 1 < $#chain ? $k + $per - 1 : $#chain)];
            my $n = @seg; my $aw = 520;
            my $bw = int(($TEXT_W - $aw * ($per - 1)) / $per);
            my @w; my $cells = '';
            for my $i (0 .. $#seg) {
                push @w, $bw; $cells .= $box->($seg[$i], $bw);
                if ($i < $#seg || ($k + $per <= $#chain && $i == $#seg)) {
                    my $e = $out{ $seg[$i] }[0];
                    my $lab = $e->[2] ? para(inline($e->[2], sz => 13, color => $MUTED), style => 'TableText', jc => 'center') : '';
                    push @w, $aw; $cells .= tc($lab . para(run("\x{2192}", color => $NAVY, sz => 28, b => 1), style => 'TableText', jc => 'center'), $aw, valign => 'center');
                }
            }
            $xml .= tbl(row($cells, cantsplit => 1), \@w, noborders => 1, mar => '<w:top w:w="40" w:type="dxa"/><w:left w:w="40" w:type="dxa"/><w:bottom w:w="40" w:type="dxa"/><w:right w:w="40" w:type="dxa"/>');
        }
        return $xml;
    }
    # Branching: one row per node, with where it leads
    my @w = (3900, 500, $TEXT_W - 4400);
    my $rows = '';
    for my $id (@order) {
        my $next = '';
        for my $e (@{ $out{$id} // [] }) {
            my $runs = '';
            $runs .= run(plain($e->[2]) . ':  ', b => 1, color => $NAVY, sz => 17) if $e->[2];
            $runs .= run(plain($label{ $e->[1] }), sz => 17, i => $e->[3] eq 'dotted');
            $runs .= run('  (back / optional)', sz => 14, color => $MUTED) if $e->[3] eq 'dotted';
            $next .= para(run("\x{25B8} ", color => $SKY, sz => 17) . $runs, style => 'TableText');
        }
        $next ||= para(run('end', i => 1, color => $MUTED, sz => 16), style => 'TableText');
        $rows .= row($box->($id, $w[0]) . tc(para(run("\x{2192}", color => $NAVY, sz => 26, b => 1), style => 'TableText', jc => 'center'), $w[1], valign => 'center')
                  . tc($next, $w[2], valign => 'center'), cantsplit => 1);
    }
    return tbl($rows, \@w, noborders => 1, mar => '<w:top w:w="30" w:type="dxa"/><w:left w:w="80" w:type="dxa"/><w:bottom w:w="30" w:type="dxa"/><w:right w:w="80" w:type="dxa"/>');
}

sub day_of { my ($y, $m, $d) = split /-/, shift; return int(timegm(0, 0, 0, $d, $m - 1, $y) / 86400) }

sub gantt {
    my @lines = @_;
    my ($title, $section) = ('', '');
    my (@tasks, %end, %start);
    for my $l (@lines) {
        if ($l =~ /^\s*title\s+(.*)/) { $title = $1; next }
        if ($l =~ /^\s*section\s+(.*)/) { $section = $1; next }
        next unless $l =~ /^\s*([^:]+?)\s*:\s*(.+)$/ && $l !~ /^\s*(dateFormat|axisFormat|gantt)/;
        my ($name, @p) = ($1, map { s/^\s+|\s+$//gr } split /,/, $2);
        my $ms = 0; if ($p[0] eq 'milestone') { $ms = 1; shift @p }
        my ($id, $st, $dur) = @p == 3 ? @p : (undef, @p);
        my $s = $st =~ /^after\s+(\w+)/ ? $end{$1} : day_of($st);
        my ($d) = $dur =~ /(\d+)/; $d //= 0;
        my $e = $s + $d;
        $end{$id} = $e if $id; $start{$id} = $s if $id;
        push @tasks, { name => $name, section => $section, s => $s, e => $e, ms => $ms };
    }
    my ($min) = sort { $a <=> $b } map { $_->{s} } @tasks;
    my ($max) = sort { $b <=> $a } map { $_->{ms} ? $_->{s} + 1 : $_->{e} } @tasks;
    my $days = $max - $min;
    my @w = (1800, 3000, (int(($TEXT_W - 4800) / $days)) x $days); $w[-1] += $TEXT_W - eval { my $t = 0; $t += $_ for @w; $t };
    my $hdr = tc(para(run('Who', b => 1, color => 'FFFFFF', sz => 16), style => 'TableText'), $w[0], fill => $DEEP)
            . tc(para(run('Task', b => 1, color => 'FFFFFF', sz => 16), style => 'TableText'), $w[1], fill => $DEEP);
    for my $i (0 .. $days - 1) {
        $hdr .= tc(para(run(strftime('%a %d', gmtime(($min + $i) * 86400)), b => 1, color => 'FFFFFF', sz => 15), style => 'TableText', jc => 'center'), $w[$i + 2], fill => $DEEP);
    }
    my $rows = row($hdr, header => 1);
    for my $t (@tasks) {
        my $cells = tc(para(run($t->{section}, color => $MUTED, sz => 16), style => 'TableText'), $w[0])
                  . tc(para(inline($t->{name}, sz => 17, b => $t->{ms}), style => 'TableText'), $w[1]);
        for my $i (0 .. $days - 1) {
            my $day = $min + $i;
            if ($t->{ms} && $day == $t->{s}) {
                $cells .= tc(para(run("\x{25C6}", color => 'A8692E', sz => 22), style => 'TableText', jc => 'center'), $w[$i + 2]);
            } elsif (!$t->{ms} && $day >= $t->{s} && $day < $t->{e}) {
                $cells .= tc(para('', style => 'TableText'), $w[$i + 2], fill => $NAVY);
            } else {
                $cells .= tc(para('', style => 'TableText'), $w[$i + 2]);
            }
        }
        $rows .= row($cells, cantsplit => 1);
    }
    return ($title ? para(run($title, b => 1, color => $NAVY), style => 'TableText', after => 60, keep => 1) : '') . tbl($rows, \@w);
}

sub gitgraph {
    my @lines = @_;
    my @branches = ('main'); my $cur = 'main'; my @commits;
    for my $l (@lines) {
        if    ($l =~ /^\s*commit(?:\s+id:\s*"([^"]*)")?/) { push @commits, [$cur, $1 // 'commit', ''] }
        elsif ($l =~ /^\s*branch\s+(\S+)/)            { push @branches, $1 unless grep { $_ eq $1 } @branches; $cur = $1 }
        elsif ($l =~ /^\s*checkout\s+(\S+)/)          { $cur = $1 }
        elsif ($l =~ /^\s*merge\s+(\S+)(?:\s+id:\s*"([^"]*)")?/) { push @commits, [$cur, $2 // "merge $1", $1] }
    }
    my %fill = (main => $NAVY, develop => '2F7D5B');
    my $n = @commits;
    my @w = (1500, (int(($TEXT_W - 1500) / $n)) x $n); $w[-1] += $TEXT_W - eval { my $t = 0; $t += $_ for @w; $t };
    my $rows = '';
    for my $b (@branches) {
        my $f = $fill{$b} // 'A8692E';
        my $cells = tc(para(run($b, b => 1, color => $f, sz => 17, code => 1, nocodeshade => 1), style => 'TableText'), $w[0], valign => 'center');
        for my $i (0 .. $n - 1) {
            my ($cb, $lab, $from) = @{ $commits[$i] };
            if ($cb eq $b) {
                my $t = ($from ? "\x{2B11} " : "\x{25CF} ") . $lab;
                $cells .= tc(para(run($t, color => 'FFFFFF', sz => 15, b => 1), style => 'TableText', jc => 'center'), $w[$i + 1], fill => $f, valign => 'center',
                             borders => join('', map { border($_, 'FFFFFF', 12) } qw(top left bottom right)));
            } else {
                $cells .= tc(para(run("\x{2500}\x{2500}", color => 'D3D9DF', sz => 15), style => 'TableText', jc => 'center'), $w[$i + 1], valign => 'center');
            }
        }
        $rows .= row($cells, cantsplit => 1);
    }
    return tbl($rows, \@w, noborders => 1);
}

# ---------------------------------------------------------------- document
sub convert {
    my ($file) = @_;
    open my $fh, '<:encoding(UTF-8)', $file or die "$file: $!";
    my @lines = <$fh>; close $fh; chomp @lines;
    my $dir = dirname($file);
    my $body = '';
    my $has_banner = grep { /assets\/banner[^"]*\.svg/ } @lines;
    if (!$has_banner) {
        my ($t) = map { /^#\s+(.*)/ ? plain($1) : () } @lines;
        $body .= banner("MIGRATION GOVERNANCE  \x{b7}  TEMPLATE", 'Server page template', $t // basename($file));
    }
    my $num;    # current ordered list
    my $i = 0;
    while ($i < @lines) {
        my $l = $lines[$i];
        if ($l =~ /^\s*$/) { undef $num; $i++; next }

        if ($l =~ /^\s*```\s*(\w*)/) {
            my $lang = $1; my @c; my ($indent) = $l =~ /^(\s*)/;
            $i++;
            while ($i < @lines && $lines[$i] !~ /^\s*```\s*$/) { my $x = $lines[$i++]; $x =~ s/^\Q$indent\E//; push @c, $x }
            $i++;
            $body .= $lang eq 'mermaid' ? mermaid(@c) : code_block(@c);
            next;
        }
        if ($l =~ /^\s*<p align="center">/ && $l !~ /<\/p>/ || $l =~ /<img\s+src="assets\//) {
            my $blk = $l;
            while ($blk !~ /<\/p>/ && $i + 1 < @lines) { $blk .= "\n" . $lines[++$i] }
            $i++;
            if ($blk =~ /<img\s+src="assets\/([\w-]+)\.svg"/) {
                my $name = $1;
                if    ($name =~ /^banner/)       { my @t = svg_texts("$dir/assets/$name.svg"); $body .= banner(@t) }
                elsif ($name =~ /^phase-(\d)/)   { $body .= phase_strip($1) }
                elsif ($name eq 'divider')       { $body .= divider() }
                elsif ($name eq 'sql-os-matrix') { $body .= matrix() }
            } elsif ($blk !~ /<a\s/) {    # a centred block of text (navigation blocks are skipped)
                my $t = $blk =~ s/<\/?p[^>]*>//gr; $t =~ s/\n/ /g;
                $body .= para(inline($t), jc => 'center');
            }
            next;
        }
        if ($l =~ /^<p align="center">(.*)<\/p>\s*$/) { $body .= para(inline($1), jc => 'center', after => 120); $i++; next }
        if ($l =~ /^\s*<table>/) {
            my $blk = '';
            $blk .= $lines[$i++] . "\n" while $i < @lines && $lines[$i] !~ /<\/table>/;
            $blk .= $lines[$i++] // '';
            $body .= html_table($blk);
            next;
        }
        if ($l =~ /^\s*<\/?details>/) { $i++; next }
        if ($l =~ /^\s*<summary>(.*)<\/summary>/) { $body .= para(run("\x{25BE} ", color => $SKY) . inline($1, color => $NAVY), keep => 1, before => 120, after => 60); $i++; next }

        if ($l =~ /^>\s*\[!(\w+)\]/) {
            my $type = uc $1; my @c; $i++;
            while ($i < @lines && $lines[$i] =~ /^>\s?(.*)/) { push @c, $1; $i++ }
            $body .= callout($type, join "\n", @c);
            next;
        }
        if ($l =~ /^>/) {
            my @c;
            while ($i < @lines && $lines[$i] =~ /^>\s?(.*)/) { push @c, $1; $i++ }
            $body .= tbl(row(tc(mini_blocks(join("\n", @c)), $TEXT_W, fill => $GREY, borders => border('left', $NAVY, 24))), [$TEXT_W], noborders => 1,
                         mar => '<w:top w:w="100" w:type="dxa"/><w:left w:w="200" w:type="dxa"/><w:bottom w:w="100" w:type="dxa"/><w:right w:w="200" w:type="dxa"/>');
            next;
        }
        if ($l =~ /^(#{1,4})\s+(.*)/) {
            my $lvl = length $1; my $t = $2;
            my $style = $lvl == 1 ? 'Heading2' : 'Heading' . ($lvl);
            $style = 'Heading4' if $lvl == 4;
            $body .= para(inline($t), style => $style) unless $lvl == 1 && !$has_banner && $i < 3;
            $i++; next;
        }
        if ($l =~ /^---+\s*$/) { $body .= divider(); $i++; next }
        if ($l =~ /^\s*\|/) {
            my @t; push @t, $lines[$i++] while $i < @lines && $lines[$i] =~ /^\s*\|/;
            $body .= pipe_table(@t);
            next;
        }
        my $lvl = ($l =~ /^(\s+)/ && length($1) >= 2) ? 1 : 0;
        (my $t = $l) =~ s/^\s+//;
        if ($t =~ /^- \[[ xX]\]\s+(.*)/) {
            $body .= para(run("\x{2610}  ", color => $NAVY) . inline($1), style => 'Check', ind => 200 + $lvl * 300); undef $num;
        } elsif ($t =~ /^[-*]\s+(.*)/) {
            $body .= para(inline($1), style => 'ListParagraph', num => $BULLET, lvl => $lvl); undef $num if !$lvl;
        } elsif ($t =~ /^\d+\.\s+(.*)/) {
            $num //= new_num(1);
            $body .= para(inline($1), style => 'ListParagraph', num => $num);
        } else {
            $body .= para(inline($t), ind => $lvl ? 560 : undef); undef $num;
        }
        $i++;
    }
    return $body;
}

my $body = '';
if (@MD > 1) {
    $body .= banner("MIGRATION GOVERNANCE  \x{b7}  COMPLETE EXPORT", 'Migration Governance',
                    "Governance guide  \x{b7}  Sysadmin guide  \x{b7}  DBA guide  \x{b7}  Scripts & VS Code  \x{b7}  Server page template",
                    'Discovery', 'Install & configure', 'Migration', 'Decommissioning');
    $body .= para(run('Contents', b => 1, color => $NAVY, sz => 32), before => 240, after => 120);
    $body .= '<w:p><w:r><w:fldChar w:fldCharType="begin" w:dirty="true"/></w:r>'
           . '<w:r><w:instrText xml:space="preserve"> TOC \o "1-2" \h \z \u </w:instrText></w:r>'
           . '<w:r><w:fldChar w:fldCharType="separate"/></w:r>'
           . run('Right-click here and choose Update Field to build the table of contents.', i => 1, color => $MUTED)
           . '<w:r><w:fldChar w:fldCharType="end"/></w:r></w:p>';
    $body .= para(run(sprintf('Exported %s from the migration-governance folder of the repository. The repository is the source; this file is a snapshot.', strftime('%Y-%m-%d', localtime)), sz => 16, color => $MUTED), before => 240);
}
for my $k (0 .. $#MD) {
    $body .= '<w:p><w:r><w:br w:type="page"/></w:r></w:p>' if $k > 0 || @MD > 1;
    $body .= convert($MD[$k]);
}

# ---------------------------------------------------------------- package
my $W = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"';
my $title = @MD > 1 ? 'Migration Governance' : plain((grep { /^#{1,2}\s/ } do { open my $f, '<:encoding(UTF-8)', $MD[0]; <$f> })[0] // basename($MD[0]));
$title =~ s/^#+\s*//; chomp $title;

my $document = qq{<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<w:document $W><w:body>$body}
  . '<w:sectPr><w:footerReference w:type="default" r:id="rId4"/><w:pgSz w:w="12240" w:h="15840"/>'
  . '<w:pgMar w:top="1080" w:right="1080" w:bottom="1080" w:left="1080" w:header="600" w:footer="500" w:gutter="0"/></w:sectPr></w:body></w:document>';

my $footer = qq{<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<w:ftr $W>}
  . para(run('Migration governance  ' . "\x{b7}" . '  ', sz => 16, color => $MUTED)
         . '<w:fldSimple w:instr=" PAGE "><w:r><w:rPr><w:color w:val="' . $MUTED . '"/><w:sz w:val="16"/></w:rPr><w:t>1</w:t></w:r></w:fldSimple>', jc => 'center')
  . '</w:ftr>';

my $styles = qq{<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles $W>
<w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="$FONT" w:hAnsi="$FONT" w:cs="$FONT" w:eastAsia="$FONT"/><w:color w:val="$TEXT"/><w:sz w:val="20"/><w:szCs w:val="20"/><w:lang w:val="en-CA"/></w:rPr></w:rPrDefault>
<w:pPrDefault><w:pPr><w:spacing w:after="100" w:line="264" w:lineRule="auto"/></w:pPr></w:pPrDefault></w:docDefaults>
<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/><w:qFormat/></w:style>
<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/>
 <w:pPr><w:keepNext/><w:spacing w:before="0" w:after="120"/><w:outlineLvl w:val="0"/></w:pPr>
 <w:rPr><w:b/><w:color w:val="$NAVY"/><w:sz w:val="48"/><w:szCs w:val="48"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/>
 <w:pPr><w:keepNext/><w:shd w:val="clear" w:color="auto" w:fill="$NAVY"/><w:spacing w:before="280" w:after="140"/><w:outlineLvl w:val="1"/></w:pPr>
 <w:rPr><w:b/><w:color w:val="FFFFFF"/><w:sz w:val="28"/><w:szCs w:val="28"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading3"><w:name w:val="heading 3"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/>
 <w:pPr><w:keepNext/><w:pBdr><w:bottom w:val="single" w:sz="6" w:space="2" w:color="$LINE"/></w:pBdr><w:spacing w:before="240" w:after="100"/><w:outlineLvl w:val="2"/></w:pPr>
 <w:rPr><w:b/><w:color w:val="$NAVY"/><w:sz w:val="24"/><w:szCs w:val="24"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading4"><w:name w:val="heading 4"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/>
 <w:pPr><w:keepNext/><w:spacing w:before="180" w:after="80"/><w:outlineLvl w:val="3"/></w:pPr>
 <w:rPr><w:b/><w:color w:val="$NAVY"/><w:sz w:val="21"/><w:szCs w:val="21"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="ListParagraph"><w:name w:val="List Paragraph"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:after="60"/></w:pPr></w:style>
<w:style w:type="paragraph" w:styleId="Check"><w:name w:val="Checklist"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:after="60"/><w:ind w:left="200"/></w:pPr></w:style>
<w:style w:type="paragraph" w:styleId="TableText"><w:name w:val="Table Text"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:after="0" w:line="252" w:lineRule="auto"/></w:pPr><w:rPr><w:sz w:val="18"/><w:szCs w:val="18"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Code"><w:name w:val="Code"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:after="0" w:line="240" w:lineRule="auto"/></w:pPr><w:rPr><w:rFonts w:ascii="$MONO" w:hAnsi="$MONO" w:cs="$MONO"/><w:sz w:val="17"/><w:szCs w:val="17"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Spacer"><w:name w:val="Spacer"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:after="100"/></w:pPr><w:rPr><w:sz w:val="8"/><w:szCs w:val="8"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="TOC1"><w:name w:val="toc 1"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:pPr><w:spacing w:before="120" w:after="40"/></w:pPr><w:rPr><w:b/><w:color w:val="$NAVY"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="TOC2"><w:name w:val="toc 2"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:pPr><w:spacing w:after="20"/><w:ind w:left="280"/></w:pPr></w:style>
</w:styles>};

my $abs = '<w:abstractNum w:abstractNumId="0"><w:multiLevelType w:val="hybridMultilevel"/>'
  . "<w:lvl w:ilvl=\"0\"><w:start w:val=\"1\"/><w:numFmt w:val=\"bullet\"/><w:lvlText w:val=\"\x{2022}\"/><w:lvlJc w:val=\"left\"/><w:pPr><w:ind w:left=\"520\" w:hanging=\"260\"/></w:pPr><w:rPr><w:color w:val=\"$NAVY\"/></w:rPr></w:lvl>"
  . "<w:lvl w:ilvl=\"1\"><w:start w:val=\"1\"/><w:numFmt w:val=\"bullet\"/><w:lvlText w:val=\"\x{2013}\"/><w:lvlJc w:val=\"left\"/><w:pPr><w:ind w:left=\"880\" w:hanging=\"260\"/></w:pPr><w:rPr><w:color w:val=\"$SKY\"/></w:rPr></w:lvl>"
  . '</w:abstractNum>'
  . '<w:abstractNum w:abstractNumId="1"><w:multiLevelType w:val="hybridMultilevel"/>'
  . "<w:lvl w:ilvl=\"0\"><w:start w:val=\"1\"/><w:numFmt w:val=\"decimal\"/><w:lvlText w:val=\"%1.\"/><w:lvlJc w:val=\"left\"/><w:pPr><w:ind w:left=\"520\" w:hanging=\"320\"/></w:pPr><w:rPr><w:b/><w:color w:val=\"$NAVY\"/></w:rPr></w:lvl>"
  . "<w:lvl w:ilvl=\"1\"><w:start w:val=\"1\"/><w:numFmt w:val=\"lowerLetter\"/><w:lvlText w:val=\"%2.\"/><w:lvlJc w:val=\"left\"/><w:pPr><w:ind w:left=\"880\" w:hanging=\"300\"/></w:pPr></w:lvl>"
  . '</w:abstractNum>';
my $nums = join '', map {
    my ($id, $a) = @$_;
    "<w:num w:numId=\"$id\"><w:abstractNumId w:val=\"$a\"/>" . ($a == 1 ? '<w:lvlOverride w:ilvl="0"><w:startOverride w:val="1"/></w:lvlOverride>' : '') . '</w:num>'
} @NUMS;
my $numbering = qq{<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<w:numbering $W>$abs$nums</w:numbering>};

my $settings = qq{<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<w:settings $W>}
  . '<w:defaultTabStop w:val="720"/>' . (@MD > 1 ? '<w:updateFields w:val="true"/>' : '') . '<w:compat><w:compatSetting w:name="compatibilityMode" w:uri="http://schemas.microsoft.com/office/word" w:val="15"/></w:compat></w:settings>';

my $content_types = q{<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
<Override PartName="/word/numbering.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.numbering+xml"/>
<Override PartName="/word/settings.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml"/>
<Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/>
<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
</Types>};

my $rels = q{<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
</Relationships>};

my $doc_rels = q{<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/numbering" Target="numbering.xml"/>
<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/settings" Target="settings.xml"/>
<Relationship Id="rId4" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" Target="footer1.xml"/>
</Relationships>};

my $core = qq{<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
<dc:title>} . esc($title) . q{</dc:title></cp:coreProperties>};

my @parts = (
    ['[Content_Types].xml', $content_types], ['_rels/.rels', $rels],
    ['word/document.xml', $document], ['word/styles.xml', $styles], ['word/numbering.xml', $numbering],
    ['word/settings.xml', $settings], ['word/footer1.xml', $footer],
    ['word/_rels/document.xml.rels', $doc_rels], ['docProps/core.xml', $core],
);
my $z;
for my $p (@parts) {
    utf8::encode(my $data = $p->[1]);
    if (!$z) { $z = IO::Compress::Zip->new($OUT, Name => $p->[0], Method => 8) or die $ZipError }
    else     { $z->newStream(Name => $p->[0], Method => 8) }
    $z->print($data);
}
$z->close;
print "wrote $OUT\n";
