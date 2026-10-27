<?php

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Checks packaging/freebsd/clipboardbridge.inc against stand-ins for the
// parts of OPNsense it calls (CI's packaging job): php tools/e2e/opnsense-hook.php

if (!function_exists('gettext')) {
    function gettext($s)
    {
        return $s;
    }
}

class FirewallStandIn
{
    public $anchors = [];

    public function registerAnchor($name, $type = 'fw', $priority = 0, $placement = 'tail', $quick = false)
    {
        $this->anchors[] = [$name, $type, $placement, $quick];
    }
}

require __DIR__ . '/../../packaging/freebsd/clipboardbridge.inc';

$fw = new FirewallStandIn();
clipboardbridge_firewall($fw);
if ($fw->anchors !== [['clipboardbridge', 'fw', 'tail', false]]) {
    fwrite(STDERR, 'clipboardbridge_firewall registered ' . json_encode($fw->anchors) . "\n");
    exit(1);
}
$services = clipboardbridge_services();
$installed = is_file('/usr/local/etc/rc.d/clipboardbridge');
if (count($services) !== ($installed ? 1 : 0)) {
    fwrite(STDERR, 'clipboardbridge_services returned ' . json_encode($services) . "\n");
    exit(1);
}
echo "the OPNsense hook registers the anchor\n";
