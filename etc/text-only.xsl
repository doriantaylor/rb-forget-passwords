<?xml version="1.0"?>
<xsl:stylesheet version="1.0"
   xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
   xmlns:html="http://www.w3.org/1999/xhtml"
   xmlns:x="urn:x-dummy"
   exclude-result-prefixes="html x">

<xsl:output method="text" media-type="text/plain" omit-xml-declaration="yes"/>

<xsl:strip-space elements="*"/>

<xsl:template name="repeat">
  <xsl:param name="string" select="''"/>
  <xsl:param name="n" select="1"/>
  <xsl:value-of select="$string"/>
  <xsl:if test="$n &gt; 1">
    <xsl:call-template name="repeat">
      <xsl:with-param name="string" select="$string"/>
      <xsl:with-param name="n" select="$n - 1"/>
    </xsl:call-template>
  </xsl:if>
</xsl:template>

<xsl:template match="/">
<xsl:apply-templates select="/html/body|/html:html/html:body"/>
</xsl:template>

<xsl:template match="body|html:body">
<xsl:apply-templates select="*"/>
</xsl:template>

<!-- link text <https://...> -->
<xsl:template match="a[@href]|html:a[@href]">
<xsl:apply-templates/>
<xsl:text disable-output-escaping="yes"> &lt;</xsl:text>
<xsl:value-of select="normalize-space(@href)"/>
<xsl:text disable-output-escaping="yes">&gt; </xsl:text>
</xsl:template>

<x:headings>
  <x:h1>#</x:h1>
  <x:h2>=</x:h2>
  <x:h3>~</x:h3>
  <x:h4>-</x:h4>
  <x:h5>-</x:h5>
  <x:h6>-</x:h6>
</x:headings>

<xsl:variable name="headings" select="document('')/xsl:stylesheet/x:headings/*"/>

<xsl:template match="html:p[normalize-space(.) != '']">
<xsl:apply-templates/>
<xsl:text>

</xsl:text>
</xsl:template>

<xsl:template match="html:h1|html:h2|html:h3|html:h4|html:h5|html:h6">
<xsl:variable name="text">
  <xsl:apply-templates/>
</xsl:variable>
<xsl:value-of select="$text" disable-output-escaping="yes"/>
<xsl:if test="string-length(normalize-space($text))">
<xsl:text>
</xsl:text>
<xsl:variable name="ln" select="local-name()"/>

<xsl:call-template name="repeat">
  <xsl:with-param name="string"
                  select="normalize-space($headings[local-name(.) = $ln])"/>
  <xsl:with-param name="n" select="string-length($text)"/>
</xsl:call-template>
<xsl:text>

</xsl:text>
</xsl:if>
</xsl:template>

<!-- stuff that we never want to render in text -->
<xsl:template match="html:img|html:object|html:iframe|html:form"/>

<xsl:variable name="vws"
  select="'&#x09;&#x0a;&#x0d;&#x85;&#xa0;&#x2028;&#x2029;'"/>

<xsl:template match="text()">
<xsl:variable name="_" select="translate(., $vws, ' ')"/>
<xsl:variable name="starts-with-ws" select="starts-with($_, ' ')"/>
<xsl:variable name="ends-with-ws"
              select="substring($_, string-length($_)) = ' '"/>

<xsl:if test="$starts-with-ws">
<xsl:text> </xsl:text>
</xsl:if>
<xsl:value-of select="normalize-space($_)" disable-output-escaping="yes"/>
<xsl:if test="$ends-with-ws">
<xsl:text> </xsl:text>
</xsl:if>

</xsl:template>

<xsl:template match="*">
<xsl:apply-templates select="text()|*"/>
</xsl:template>

</xsl:stylesheet>
