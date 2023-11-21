#pragma once

enum ProtocolUdpDependant
{
    BOOTPS = 67,
    BOOTPC = 68,
    DNS = 53, // DNS is suited for both TCP and UDP, but it is using UDP by default
};