<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
    <xsl:output method="xml" omit-xml-declaration="yes" indent="yes"/>
    <xsl:template match="/UserInfo">
        <Person>
            <Id><xsl:value-of select="sub"/></Id>
            <FullName><xsl:value-of select="name"/></FullName>
            <Mail><xsl:value-of select="email"/></Mail>
        </Person>
    </xsl:template>
</xsl:stylesheet>
