#pragma once
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define BUF_SUBOPT 1024

#define IAC 0xFF
#define DONT 0xFE
#define DO 0xFD
#define WONT 0xFC
#define WILL 0xFB
#define SB 0xFA
#define SE 0xF0
#define NOP 0xF1
#define DM 0xF2
#define BRK 0xF3
#define IP 0xF4
#define AO 0xF5
#define AYT 0xF6
#define EC 0xF7
#define EL 0xF8
#define GA 0xF9

#define BINARY 0x00
#define ECHO 0x01
#define RCP 0x02
#define SGA 0x03
#define NAMS 0x04
#define STATUS 0x05
#define TM 0x06
#define RCTE 0x07
#define NAOL 0x08
#define NAOP 0x09
#define NAOCRD 0x0A
#define NAOHTS 0x0B
#define NAOHTD 0x0C
#define NAOFFD 0x0D
#define NAOVTS 0x0E
#define NAOVTD 0x0F
#define NAOLFD 0x10
#define XASCII 0x11
#define LOGOUT 0x12
#define BM 0x13
#define DET 0x14
#define SUPDUP 0x15
#define SUPDUPOUTPUT 0x16
#define SNDLOC 0x17
#define TTYPE 0x18
#define EOR 0x19
#define TUID 0x1A
#define OUTMRK 0x1B
#define TTYLOC 0x1C
#define VT3270REGIME 0x1D
#define X3PAD 0x1E
#define NAWS 0x1F
#define TSPEED 0x20
#define LFLOW 0x21
#define LINEMODE 0x22
#define XDISPLOC 0x23
#define OLD_ENVIRON 0x24
#define AUTHENTICATION 0x25
#define ENCRYPT 0x26
#define NEW_ENVIRON 0x27
#define TN3270E 0x28
#define XAUTH 0x29
#define CHARSET 0x2A
#define RSP 0x2B
#define COM_PORT_OPTION 0x2C
#define SUPPRESS_LOCAL_ECHO 0x2D
#define TLS 0x2E
#define KERMIT 0x2F
#define SEND_URL 0x30
#define FORWARD_X 0x31
#define PRAGMA_LOGON 0x32
#define SSPI_LOGON 0x33
#define PRAGMA_HEARTBEAT 0x34

#define TELNET_COMMANDS                                                                                                \
    X(IAC, "IAC")                                                                                                      \
    X(DONT, "DONT")                                                                                                    \
    X(DO, "DO")                                                                                                        \
    X(WONT, "WONT")                                                                                                    \
    X(WILL, "WILL")                                                                                                    \
    X(SB, "SB")                                                                                                        \
    X(SE, "SE")                                                                                                        \
    X(NOP, "NOP")                                                                                                      \
    X(DM, "DM")                                                                                                        \
    X(BRK, "BRK")                                                                                                      \
    X(IP, "IP")                                                                                                        \
    X(AO, "AO")                                                                                                        \
    X(AYT, "AYT")                                                                                                      \
    X(EC, "EC")                                                                                                        \
    X(EL, "EL")                                                                                                        \
    X(GA, "GA")                                                                                                        \
    X(BINARY, "BINARY")                                                                                                \
    X(ECHO, "ECHO")                                                                                                    \
    X(RCP, "RCP")                                                                                                      \
    X(SGA, "SGA")                                                                                                      \
    X(NAMS, "NAMS")                                                                                                    \
    X(STATUS, "STATUS")                                                                                                \
    X(TM, "TM")                                                                                                        \
    X(RCTE, "RCTE")                                                                                                    \
    X(NAOL, "NAOL")                                                                                                    \
    X(NAOP, "NAOP")                                                                                                    \
    X(NAOCRD, "NAOCRD")                                                                                                \
    X(NAOHTS, "NAOHTS")                                                                                                \
    X(NAOHTD, "NAOHTD")                                                                                                \
    X(NAOFFD, "NAOFFD")                                                                                                \
    X(NAOVTS, "NAOVTS")                                                                                                \
    X(NAOVTD, "NAOVTD")                                                                                                \
    X(NAOLFD, "NAOLFD")                                                                                                \
    X(XASCII, "XASCII")                                                                                                \
    X(LOGOUT, "LOGOUT")                                                                                                \
    X(BM, "BM")                                                                                                        \
    X(DET, "DET")                                                                                                      \
    X(SUPDUP, "SUPDUP")                                                                                                \
    X(SUPDUPOUTPUT, "SUPDUPOUTPUT")                                                                                    \
    X(SNDLOC, "SNDLOC")                                                                                                \
    X(TTYPE, "TTYPE")                                                                                                  \
    X(EOR, "EOR")                                                                                                      \
    X(TUID, "TUID")                                                                                                    \
    X(OUTMRK, "OUTMRK")                                                                                                \
    X(TTYLOC, "TTYLOC")                                                                                                \
    X(VT3270REGIME, "VT3270REGIME")                                                                                    \
    X(X3PAD, "X3PAD")                                                                                                  \
    X(NAWS, "NAWS")                                                                                                    \
    X(TSPEED, "TSPEED")                                                                                                \
    X(LFLOW, "LFLOW")                                                                                                  \
    X(LINEMODE, "LINEMODE")                                                                                            \
    X(XDISPLOC, "XDISPLOC")                                                                                            \
    X(OLD_ENVIRON, "OLD_ENVIRON")                                                                                      \
    X(AUTHENTICATION, "AUTHENTICATION")                                                                                \
    X(ENCRYPT, "ENCRYPT")                                                                                              \
    X(NEW_ENVIRON, "NEW_ENVIRON")                                                                                      \
    X(TN3270E, "TN3270E")                                                                                              \
    X(XAUTH, "XAUTH")                                                                                                  \
    X(CHARSET, "CHARSET")                                                                                              \
    X(RSP, "RSP")                                                                                                      \
    X(COM_PORT_OPTION, "COM_PORT_OPTION")                                                                              \
    X(SUPPRESS_LOCAL_ECHO, "SUPPRESS_LOCAL_ECHO")                                                                      \
    X(TLS, "TLS")                                                                                                      \
    X(KERMIT, "KERMIT")                                                                                                \
    X(SEND_URL, "SEND_URL")                                                                                            \
    X(FORWARD_X, "FORWARD_X")                                                                                          \
    X(PRAGMA_LOGON, "PRAGMA_LOGON")                                                                                    \
    X(SSPI_LOGON, "SSPI_LOGON")                                                                                        \
    X(PRAGMA_HEARTBEAT, "PRAGMA_HEARTBEAT")

#define X(code, name) [code] = name,
#pragma GCC diagnostic ignored "-Wunused-variable"
static const char *TELNET_MAP[] = {TELNET_COMMANDS};
#pragma GCC diagnostic pop
#undef X
