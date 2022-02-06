<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<parameterProfile>
    <name>wolfssl_default</name>
    <description>Default Profile for Wolfssl</description>
    <type>WOLFSSL</type>
    <role>SERVER</role>
    <Parameter>
        <cmdParameter>-c [cert] -k [key] -v 4</cmdParameter>
        <type>CERTIFICATE_KEY</type>
    </Parameter>
    <Parameter>
        <cmdParameter>-d -b</cmdParameter>
        <type>NONE</type>
    </Parameter>
    <Parameter>
        <cmdParameter>-p [port]</cmdParameter>
        <type>HOST_PORT</type>
    </Parameter>
</parameterProfile>
