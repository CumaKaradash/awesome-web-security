> [!ÖNEMLİ]  
> Web Pentest Eğitimim [Black Hat 2025](https://www.blackhat.com/us-25/training/schedule/index.html#web-hacking-from--to--44516) tarafından kabul edildi 🎉🎉🎉 Lütfen kursuma katılın 🤓
>
> Bu unutulmaz anı kutlamak için (ve bir süredir depoyu güncellemediğim için özür dileyerek), önümüzdeki haftalarda bu uzun süredir devam eden deponun tüm içeriğini, bu yıllar boyunca gelişen bilgi ve püf noktalarını yakalamak için tamamen yenileyeceğim.

# Harika Web Güvenliği [![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)

[<img src="https://upload.wikimedia.org/wikipedia/commons/6/61/HTML5_logo_and_wordmark.svg" align="right" width="70">](https://www.w3.org/TR/html5/)

> 🐶 Web Güvenliği materyalleri ve kaynakları için seçilmiş liste.

Söylemeye gerek yok, çoğu web sitesi sonunda güvenlik açıklarına yol açabilecek çeşitli hatalardan muzdariptir. Bu neden bu kadar sık yaşanıyor? Yanlış yapılandırma, mühendislerin güvenlik becerilerindeki eksiklikler vb. gibi birçok faktör söz konusu olabilir. Bununla mücadele etmek için, en son sızma testi tekniklerini öğrenmek için seçilmiş bir Web Güvenliği materyalleri ve kaynakları listesi sunuyorum. Öncelikle "[Web güvenlik araştırmacısı olmak mı istiyorsunuz?](https://portswigger.net/blog/so-you-want-to-be-a-web-security-researcher)" makalesini okumanızı şiddetle tavsiye ederim.

*Lütfen katkıda bulunmadan önce [katkı kurallarını](CONTRIBUTING.md) okuyun.*

---

<p align="center"><b>🌈 Sızma testi becerilerinizi güçlendirmek mi istiyorsunuz?</b><br>Size bazı <a href="https://github.com/apsdehal/awesome-ctf" target="_blank">harika CTF</a> oyunları oynamanızı öneririm.</p>

---

Bu harika listeyi beğendiyseniz ve desteklemek isterseniz, [Patreon](https://www.patreon.com/boik) sayfama göz atabilirsiniz :)<br>Ayrıca, [depolarımı](https://github.com/qazbnm456) kontrol etmeyi unutmayın 🐾 veya [Twitter](https://twitter.com/qazbnm456) üzerinden merhaba deyin!

## İçindekiler

- [Özetler](#digests)
- [Forumlar](#forums)
- [Giriş](#intro)
  - [XSS](#xss---cross-site-scripting)
  - [Prototype Kirliliği](#prototype-pollution)
  - [CSV Enjeksiyonu](#csv-injection)
  - [SQL Enjeksiyonu](#sql-injection)
  - [Komut Enjeksiyonu](#command-injection)
  - [ORM Enjeksiyonu](#orm-injection)
  - [FTP Enjeksiyonu](#ftp-injection)
  - [XXE](#xxe---xml-external-entity)
  - [CSRF](#csrf---cross-site-request-forgery)
  - [Tıklama Hırsızlığı](#clickjacking)
  - [SSRF](#ssrf---server-side-request-forgery)
  - [Web Önbellek Zehirleme](#web-cache-poisoning)
  - [Göreli Yol Üzerine Yazma](#relative-path-overwrite)
  - [Açık Yönlendirme](#open-redirect)
  - [SAML](#saml)
  - [Dosya Yükleme](#upload)
  - [Rails](#rails)
  - [AngularJS](#angularjs)
  - [ReactJS](#reactjs)
  - [SSL/TLS](#ssltls)
  - [Webmail](#webmail)
  - [NFS](#nfs)
  - [AWS](#aws)
  - [Azure](#azure)
  - [Parmak İzi](#fingerprint)
  - [Alt Alan Adı Keşfi](#sub-domain-enumeration)
  - [Kripto](#crypto)
  - [Web Kabuğu](#web-shell)
  - [OSINT](#osint)
  - [DNS Yeniden Bağlama](#dns-rebinding)
  - [Serileştirme](#deserialization)
  - [OAuth](#oauth)
  - [JWT](#jwt)
- [Atlatma Teknikleri](#evasions)
  - [XXE](#evasions-xxe)
  - [İçerik Güvenlik Politikası](#evasions-csp)
  - [Web Uygulama Güvenlik Duvarı](#evasions-waf)
  - [JSMVC](#evasions-jsmvc)
  - [Kimlik Doğrulama](#evasions-authentication)
- [Püf Noktaları](#tricks)
  - [CSRF](#tricks-csrf)
  - [Tıklama Hırsızlığı](#tricks-clickjacking)
  - [Uzaktan Kod Çalıştırma](#tricks-rce)
  - [XSS](#tricks-xss)
  - [SQL Enjeksiyonu](#tricks-sql-injection)
  - [NoSQL Enjeksiyonu](#tricks-nosql-injection)
  - [FTP Enjeksiyonu](#tricks-ftp-injection)
  - [XXE](#tricks-xxe)
  - [SSRF](#tricks-ssrf)
  - [Web Önbellek Zehirleme](#tricks-web-cache-poisoning)
  - [Başlık Enjeksiyonu](#tricks-header-injection)
  - [URL](#tricks-url)
  - [Serileştirme](#tricks-deserialization)
  - [OAuth](#tricks-oauth)
  - [Diğerleri](#tricks-others)
- [Tarayıcı Sömürüsü](#browser-exploitation)
- [Kavram Kanıtları](#pocs)
  - [Veritabanı](#pocs-database)
- [Kılavuzlar](#cheetsheets)
- [Araçlar](#tools)
  - [Denetim](#tools-auditing)
  - [Komut Enjeksiyonu](#tools-command-injection)
  - [Keşif](#tools-reconnaissance)
    - [OSINT](#tools-osint)
    - [Alt Alan Adı Keşfi](#tools-sub-domain-enumeration)
  - [Kod Üretme](#tools-code-generating)
  - [Fuzzing](#tools-fuzzing)
  - [Tarama](#tools-scanning)
  - [Sızma Testi](#tools-penetration-testing)
  - [Sızıntı Tespiti](#tools-leaking)
  - [Ofansif](#tools-offensive)
    - [XSS](#tools-xss)
    - [SQL Enjeksiyonu](#tools-sql-injection)
    - [Şablon Enjeksiyonu](#tools-template-injection)
    - [XXE](#tools-xxe)
    - [CSRF](#tools-csrf)
    - [SSRF](#tools-ssrf)
  - [Tespit Etme](#tools-detecting)
  - [Önleme](#tools-preventing)
  - [Vekil Sunucu](#tools-proxy)
  - [Web Kabuğu](#tools-webshell)
  - [Ayrıştırıcı](#tools-disassembler)
  - [Tersine Çevirici](#tools-decompiler)
  - [DNS Yeniden Bağlama](#tools-dns-rebinding)
  - [Diğerleri](#tools-others)
- [Sosyal Mühendislik Veritabanı](#social-engineering-database)
- [Bloglar](#blogs)
- [Twitter Kullanıcıları](#twitter-users)
- [Uygulamalar](#practices)
  - [Uygulama](#practices-application)
  - [AWS](#practices-aws)
  - [XSS](#practices-xss)
  - [ModSecurity / OWASP ModSecurity Çekirdek Kural Seti](#practices-modsecurity)
- [Topluluk](#community)
- [Çeşitli](#miscellaneous)

## Özetler

- [Hacker101](https://www.hacker101.com/) - [hackerone](https://www.hackerone.com/start-hacking) tarafından yazılmıştır.
- [The Daily Swig - Web güvenliği özeti](https://portswigger.net/daily-swig) - [PortSwigger](https://portswigger.net/) tarafından yazılmıştır.
- [Netsparker Web Uygulama Güvenliği Bölgesi](https://www.netsparker.com/blog/web-security/) - [Netsparker](https://www.netsparker.com/) tarafından yazılmıştır.
- [Siber Güvenliğe Yeni Başlayanlar İçin](https://www.sneakymonkey.net/2017/04/23/infosec-newbie/) - [Mark Robinson](https://www.sneakymonkey.net/) tarafından yazılmıştır.
- [Öğrenmenin Büyüsü](https://bitvijays.github.io/) - [@bitvijays](https://bitvijays.github.io/aboutme.html) tarafından yazılmıştır.
- [CTF Alan Kılavuzu](https://trailofbits.github.io/ctf/) - [Trail of Bits](https://www.trailofbits.com/) tarafından yazılmıştır.
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/) - [@swisskyrepo](https://github.com/swisskyrepo) tarafından yazılmıştır.
- [Kısa ve Öz Güvenlik](https://tldrsec.com/) - En iyi güvenlik araçları, blog yazıları ve güvenlik araştırmalarının haftalık özeti.

## Forumlar

- [Phrack Dergisi](http://www.phrack.org/) - Hacker'lar için ve hacker'lar tarafından yazılan e-dergi.
- [Hacker Haberleri](https://thehackernews.com/) - Güvenlik ciddi bir iştir.
- [Haftalık Güvenlik](https://securityweekly.com/) - Güvenlik podcast ağı.
- [Kayıt Defteri](http://www.theregister.co.uk/) - Bizi besleyen eli ısırmak.
- [Karanlık Okuma](https://www.darkreading.com/Default.asp) - Bilgi Güvenliği Topluluğunu Birbirine Bağlamak.
- [HackKazı](http://en.hackdig.com/) - Hacker'lar için yüksek kaliteli web güvenliği makaleleri.

<a name="intro"></a>
## Giriş

<a name="xss"></a>
### XSS - Siteler Arası Komut Çalıştırma

- [Siteler Arası Komut Çalıştırma – Uygulama Güvenliği – Google](https://www.google.com/intl/sw/about/appsecurity/learning/xss/) - [Google](https://www.google.com/) tarafından yazılmıştır.
- [H5SC](https://github.com/cure53/H5SC) - [@cure53](https://github.com/cure53) tarafından yazılmıştır.
- [AwesomeXSS](https://github.com/s0md3v/AwesomeXSS) - [@s0md3v](https://github.com/s0md3v) tarafından yazılmıştır.
- [XSS.png](https://github.com/LucaBongiorni/XSS.png) - Written by @jackmasa.
- [C.XSS Guide](https://excess-xss.com/) - Written by [@JakobKallin](https://github.com/JakobKallin) and [Irene Lobo Valbuena](https://www.linkedin.com/in/irenelobovalbuena/).
- [THE BIG BAD WOLF - XSS AND MAINTAINING ACCESS](http://www.paulosyibelo.com/2018/06/the-big-bad-wolf-xss-and-maintaining.html) - Written by [Paulos Yibelo](http://www.paulosyibelo.com/).
- [payloadbox/xss-payload-list](https://github.com/payloadbox/xss-payload-list) - Written by [@payloadbox](https://github.com/payloadbox).
- [PayloadsAllTheThings - XSS Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection) - Written by [@swisskyrepo](https://github.com/swisskyrepo).

<a name="prototype-pollution"></a>
### Prototip Kirliliği

- [NodeJS uygulamasında prototip kirliliği saldırısı](https://github.com/HoLyVieR/prototype-pollution-nsec18/blob/master/paper/JavaScript_prototype_pollution_attack_in_NodeJS.pdf) - [@HoLyVieR](https://github.com/HoLyVieR) tarafından yazılmıştır.
- [Prototip kirliliğinden yararlanma – Kibana'da Uzaktan Kod Çalıştırma (CVE-2019-7609)](https://research.securitum.com/prototype-pollution-rce-kibana-cve-2019-7609/) - [@securitymb](https://twitter.com/securitymb) tarafından yazılmıştır.
- [Gerçek Dünyada JavaScript - 1](https://blog.p6.is/Real-World-JS-1/) - [@po6ix](https://twitter.com/po6ix) tarafından yazılmıştır.

<a name="csv-injection"></a>
### CSV Enjeksiyonu

- [CSV Enjeksiyonu -> Pornhub'da Meterpreter](https://news.webamooz.com/wp-content/uploads/bot/offsecmag/147.pdf) - [Andy](https://blog.zsec.uk/) tarafından yazılmıştır.
- [CSV Enjeksiyonunun Son Derece Hafife Alınan Tehlikeleri](http://georgemauer.net/2017/10/07/csv-injection.html) - [George Mauer](http://georgemauer.net/) tarafından yazılmıştır.
- [PayloadsAllTheThings - CSV Enjeksiyonu](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CSV%20Injection) - [@swisskyrepo](https://github.com/swisskyrepo) tarafından yazılmıştır.

<a name="sql-injection"></a>
### SQL Enjeksiyonu

- [SQL Enjeksiyonu Kopya Kağıdı](https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/) - [@netsparker](https://twitter.com/netsparker) tarafından yazılmıştır.
- [SQL Enjeksiyonu Wiki](https://sqlwiki.netspi.com/) - [NETSPI](https://www.netspi.com/) tarafından yazılmıştır.
- [SQL Enjeksiyonu Cep Rehberi](https://websec.ca/kb/sql_injection) - [@LightOS](https://twitter.com/LightOS) tarafından yazılmıştır.
- [payloadbox/sql-injection-payload-list](https://github.com/payloadbox/sql-injection-payload-list) - [@payloadbox](https://github.com/payloadbox) tarafından yazılmıştır.
- [PayloadsAllTheThings - SQL Enjeksiyonu](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection) - [@swisskyrepo](https://github.com/swisskyrepo) tarafından yazılmıştır.

<a name="command-injection"></a>
### Komut Enjeksiyonu

- [resolv.rb'de olası komut enjeksiyonu](https://github.com/ruby/ruby/pull/1777) - [@drigg3r](https://github.com/drigg3r) tarafından yazılmıştır.
- [payloadbox/command-injection-payload-list](https://github.com/payloadbox/command-injection-payload-list) - [@payloadbox](https://github.com/payloadbox) tarafından yazılmıştır.
- [PayloadsAllTheThings - Komut Enjeksiyonu](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection) - [@swisskyrepo](https://github.com/swisskyrepo) tarafından yazılmıştır.

<a name="orm-injection"></a>
### ORM Enjeksiyonu

- [Pentester'lar için HQL](http://blog.h3xstream.com/2014/02/hql-for-pentesters.html) - [@h3xstream](https://twitter.com/h3xstream/) tarafından yazılmıştır.
- [HQL: Hiper Çılgın Sorgu Dili (veya HQL enjeksiyonu içinde tüm SQL API'sine nasıl erişilir?)](https://www.synacktiv.com/ressources/hql2sql_sstic_2015_en.pdf) - [@_m0bius](https://twitter.com/_m0bius) tarafından yazılmıştır.
- [ORM2Pwn: Hibernate ORM'da enjeksiyonlardan yararlanma](https://www.slideshare.net/0ang3el/orm2pwn-exploiting-injections-in-hibernate-orm) - [Mikhail Egorov](https://0ang3el.blogspot.tw/) tarafından yazılmıştır.
- [ORM Enjeksiyonu](https://www.slideshare.net/simone.onofri/orm-injection) - [Simone Onofri](https://onofri.org/) tarafından yazılmıştır.

<a name="ftp-injection"></a>
### FTP Enjeksiyonu

- [Uyarı: Java/Python FTP Enjeksiyonları Güvenlik Duvarını Atlamaya İzin Veriyor](http://blog.blindspotsecurity.com/2017/02/advisory-javapython-ftp-injections.html) - [Timothy Morgan](https://plus.google.com/105917618099766831589) tarafından yazılmıştır.
- [XXE üzerinden SMTP - Java'nın XML ayrıştırıcısını kullanarak e-posta gönderme](https://shiftordie.de/blog/2017/02/18/smtp-over-xxe/) - [Alexander Klink](https://shiftordie.de/) tarafından yazılmıştır.

<a name="xxe"></a>
### XXE - XML Harici Varlık

- [XXE](https://phonexicum.github.io/infosec/xxe.html) - [@phonexicum](https://twitter.com/phonexicum) tarafından yazılmıştır.
- [XML harici varlık (XXE) enjeksiyonu](https://portswigger.net/web-security/xxe) - [portswigger](https://portswigger.net/) tarafından yazılmıştır.
- [XML Şeması, DTD ve Varlık Saldırıları](https://www.vsecurity.com/download/publications/XMLDTDEntityAttacks.pdf) - [Timothy D. Morgan](https://twitter.com/ecbftw) ve Omar Al Ibrahim tarafından yazılmıştır.
- [payloadbox/xxe-injection-payload-list](https://github.com/payloadbox/xxe-injection-payload-list) - [@payloadbox](https://github.com/payloadbox) tarafından yazılmıştır.
- [PayloadsAllTheThings - XXE Enjeksiyonu](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection) - Çeşitli katkıcılar tarafından yazılmıştır.

<a name="csrf"></a>
### CSRF - Siteler Arası İstek Sahteciliği

- [CSRF'yi Ortadan Kaldırmak](https://medium.com/@jrozner/wiping-out-csrf-ded97ae7e83f) - [@jrozner](https://medium.com/@jrozner) tarafından yazılmıştır.
- [PayloadsAllTheThings - CSRF Enjeksiyonu](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CSRF%20Injection) - [@swisskyrepo](https://github.com/swisskyrepo) tarafından yazılmıştır.

<a name="clickjacking"></a>
### Tıklama Hırsızlığı

- [Tıklama Hırsızlığı](https://www.imperva.com/learn/application-security/clickjacking/) - [Imperva](https://www.imperva.com/) tarafından yazılmıştır.
- [X-Frame-Options: Tıklama Hırsızlığı Hakkında Her Şey?](https://github.com/cure53/Publications/blob/master/xfo-clickjacking.pdf?raw=true) - [Mario Heiderich](http://www.slideshare.net/x00mario) tarafından yazılmıştır.

<a name="ssrf"></a>
### SSRF - Sunucu Tarafı İstek Sahteciliği

- [SSRF kutsal kitabı. Kopya Kağıdı](https://docs.google.com/document/d/1v1TkWZtrhzRLy0bYXBcdLUedXGb9njTNIJXa3u9akHM/edit) - [Wallarm](https://wallarm.com/) tarafından yazılmıştır.
- [PayloadsAllTheThings - Sunucu Tarafı İstek Sahteciliği](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery) - [@swisskyrepo](https://github.com/swisskyrepo) tarafından yazılmıştır.

<a name="web-cache-poisoning"></a>
### Web Önbellek Zehirleme

- [Pratik Web Önbellek Zehirleme](https://portswigger.net/blog/practical-web-cache-poisoning) - [@albinowax](https://twitter.com/albinowax) tarafından yazılmıştır.
- [PayloadsAllTheThings - Web Önbellek Aldatmacası](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Web%20Cache%20Deception) - [@swisskyrepo](https://github.com/swisskyrepo) tarafından yazılmıştır.

<a name="relative-path-overwrite"></a>
### Göreli Yol Üzerine Yazma

- [Göreli yol üzerine yazma yoluyla stil enjeksiyonunun geniş ölçekli analizi](https://blog.acolyer.org/2018/05/28/large-scale-analysis-of-style-injection-by-relative-path-overwrite/) - [The Morning Paper](https://blog.acolyer.org/) tarafından yazılmıştır.
- [MBSD Teknik Beyaz Kağıdı - Birkaç RPO sömürme tekniği](https://www.mbsd.jp/Whitepaper/rpo.pdf) - [Mitsui Bussan Secure Directions, Inc.](https://www.mbsd.jp/) tarafından yazılmıştır.

<a name="open-redirect"></a>
### Açık Yönlendirme

- [Açık Yönlendirme Güvenlik Açığı](https://s0cket7.com/open-redirect-vulnerability/) - [s0cket7](https://s0cket7.com/) tarafından yazılmıştır.
- [payloadbox/open-redirect-payload-list](https://github.com/payloadbox/open-redirect-payload-list) - [@payloadbox](https://github.com/payloadbox) tarafından yazılmıştır.
- [PayloadsAllTheThings - Açık Yönlendirme](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Open%20Redirect) - [@swisskyrepo](https://github.com/swisskyrepo) tarafından yazılmıştır.

<a name="saml"></a>
### Güvenlik Onaylama İşaretleme Dili (SAML)

- [SAML'da Hataları Nasıl Avlarsınız; Bir Metodoloji - Bölüm I](https://epi052.gitlab.io/notes-to-self/blog/2019-03-07-how-to-test-saml-a-methodology/) - [epi](https://epi052.gitlab.io/notes-to-self/) tarafından yazılmıştır.
- [SAML'da Hataları Nasıl Avlarsınız; Bir Metodoloji - Bölüm II](https://epi052.gitlab.io/notes-to-self/blog/2019-03-13-how-to-test-saml-a-methodology-part-two/) - [epi](https://epi052.gitlab.io/notes-to-self/) tarafından yazılmıştır.
- [SAML'da Hataları Nasıl Avlarsınız; Bir Metodoloji - Bölüm III](https://epi052.gitlab.io/notes-to-self/blog/2019-03-16-how-to-test-saml-a-methodology-part-three/) - [epi](https://epi052.gitlab.io/notes-to-self/) tarafından yazılmıştır.
- [PayloadsAllTheThings - SAML Enjeksiyonu](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SAML%20Injection) - [@swisskyrepo](https://github.com/swisskyrepo) tarafından yazılmıştır.

<a name="upload"></a>
### Dosya Yükleme

- [Dosya Yükleme Kısıtlamalarını Atlama](https://www.exploit-db.com/docs/english/45074-file-upload-restrictions-bypass.pdf) - [Haboob Ekibi](https://www.exploit-db.com/author/?a=9381) tarafından yazılmıştır.
- [PayloadsAllTheThings - Güvensiz Dosyaları Yükleme](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files) - [@swisskyrepo](https://github.com/swisskyrepo) tarafından yazılmıştır.

<a name="rails"></a>
### Rails

- [Rails Güvenliği - İlk Bölüm](https://hackmd.io/s/SkuTVw5O-) - [@qazbnm456](https://github.com/qazbnm456) tarafından yazılmıştır.
- [Zen Rails Güvenlik Kontrol Listesi](https://github.com/brunofacca/zen-rails-security-checklist) - [@brunofacca](https://github.com/brunofacca) tarafından yazılmıştır.
- [Rails SQL Enjeksiyonu](https://rails-sqli.org) - [@presidentbeef](https://github.com/presidentbeef) tarafından yazılmıştır.
- [Resmi Rails Güvenlik Rehberi](http://guides.rubyonrails.org/security.html) - [Rails ekibi](https://rubyonrails.org/) tarafından yazılmıştır.

<a name="angularjs"></a>
### AngularJS

- [HTML Olmadan XSS: AngularJS ile İstemci Tarafı Şablon Enjeksiyonu](http://blog.portswigger.net/2016/01/xss-without-html-client-side-template.html) - [Gareth Heyes](https://www.blogger.com/profile/10856178524811553475) tarafından yazılmıştır.
- [DOM tabanlı Angular kum kutusu kaçışları](http://blog.portswigger.net/2017/05/dom-based-angularjs-sandbox-escapes.html) - [@garethheyes](https://twitter.com/garethheyes) tarafından yazılmıştır.

<a name="reactjs"></a>
### ReactJS

- [Sahte bir React öğesi aracılığıyla XSS](http://danlec.com/blog/xss-via-a-spoofed-react-element) - [Daniel LeCheminant](http://danlec.com/) tarafından yazılmıştır.

<a name="ssl-tls"></a>
### SSL/TLS

- [SSL & TLS Sızma Testi](https://www.aptive.co.uk/blog/tls-ssl-security-testing/) - [APTIVE](https://www.aptive.co.uk/) tarafından yazılmıştır.
- [SSL/TLS'ye Pratik Giriş](https://github.com/Hakky54/mutual-tls-ssl) - [@Hakky54](https://github.com/Hakky54) tarafından yazılmıştır.

<a name="webmail"></a>
### Webmail

- [PHP'de mail() fonksiyonu neden tehlikelidir?](https://blog.ripstech.com/2017/why-mail-is-dangerous-in-php/) - [Robin Peraglie](https://www.ripstech.com/) tarafından yazılmıştır.

<a name="nfs"></a>
### NFS

- [NFS | SIZMA TESTİ AKADEMİSİ](https://pentestacademy.wordpress.com/2017/09/20/nfs/) - [SIZMA TESTİ AKADEMİSİ](https://pentestacademy.wordpress.com/) tarafından yazılmıştır.

<a name="aws"></a>
### AWS

- [AWS DEPOLAMA SIZMA TESTİ: S3 KOVASINI TEKMELEMEK](https://rhinosecuritylabs.com/penetration-testing/penetration-testing-aws-storage/) - [Rhino Security Labs](https://rhinosecuritylabs.com/)'tan Dwight Hohnstein tarafından yazılmıştır.
- [AWS SIZMA TESTİ BÖLÜM 1. S3 KOVALARI](https://www.virtuesecurity.com/aws-penetration-testing-part-1-s3-buckets/) - [VirtueSecurity](https://www.virtuesecurity.com/) tarafından yazılmıştır.
- [AWS SIZMA TESTİ BÖLÜM 2. S3, IAM, EC2](https://www.virtuesecurity.com/aws-penetration-testing-part-2-s3-iam-ec2/) - [VirtueSecurity](https://www.virtuesecurity.com/) tarafından yazılmıştır.
- [AWS'de Talihsiz Maceralar](https://labs.f-secure.com/blog/misadventures-in-aws) - Christian Demko tarafından yazılmıştır.

<a name="azure"></a>
### Azure

- [Yaygın Azure Güvenlik Açıkları ve Yanlış Yapılandırmalar](https://rhinosecuritylabs.com/cloud-security/common-azure-security-vulnerabilities/) - [@rhinobenjamin](https://twitter.com/rhinobenjamin) tarafından yazılmıştır.
- [Bulut Güvenliği Riskleri (Bölüm 1): Azure CSV Enjeksiyon Güvenlik Açığı](https://rhinosecuritylabs.com/azure/cloud-security-risks-part-1-azure-csv-injection-vulnerability/) - [@spengietz](https://twitter.com/spengietz) tarafından yazılmıştır.

<a name="fingerprint"></a>
### Parmak İzi

<a name="sub-domain-enumeration"></a>
### Sub Domain Enumeration

- [A penetration tester’s guide to sub-domain enumeration](https://blog.appsecco.com/a-penetration-testers-guide-to-sub-domain-enumeration-7d842d5570f6) - Written by [Bharath](https://blog.appsecco.com/@yamakira_).
- [The Art of Subdomain Enumeration](https://blog.sweepatic.com/art-of-subdomain-enumeration/) - Written by [Patrik Hudak](https://blog.sweepatic.com/author/patrik/).

<a name="crypto"></a>
### Kripto

- [Uygulamalı Kripto Sertleştirme](https://bettercrypto.org/) - [The bettercrypto.org Ekibi](https://bettercrypto.org/) tarafından yazılmıştır.
- [Yan Kanal Saldırısı Nedir?](https://www.csoonline.com/article/3388647/what-is-a-side-channel-attack-how-these-end-runs-around-encryption-put-everyone-at-risk.html) - [J.M Porup](https://www.csoonline.com/author/J.M.-Porup/) tarafından yazılmıştır.

<a name="web-shell"></a>
### Web Kabuğu

- [Web Kabukları Avı](https://www.tenable.com/blog/hunting-for-web-shells) - [Jacob Baines](https://www.tenable.com/profile/jacob-baines) tarafından yazılmıştır.
- [JSP Kabukları ile Hackleme](https://blog.netspi.com/hacking-with-jsp-shells/) - [@_nullbind](https://twitter.com/_nullbind) tarafından yazılmıştır.

<a name="osint"></a>
### OSINT

- [Hacking Cryptocurrency Miners with OSINT Techniques](https://medium.com/@s3yfullah/hacking-cryptocurrency-miners-with-osint-techniques-677bbb3e0157) - Written by [@s3yfullah](https://medium.com/@s3yfullah).
- [OSINT x UCCU Workshop on Open Source Intelligence](https://www.slideshare.net/miaoski/osint-x-uccu-workshop-on-open-source-intelligence) - Written by [Philippe Lin](https://www.slideshare.net/miaoski).
- [102 Deep Dive in the Dark Web OSINT Style Kirby Plessas](https://www.youtube.com/watch?v=fzd3zkAI_o4) - Presented by [@kirbstr](https://twitter.com/kirbstr).
- [The most complete guide to finding anyone’s email](https://www.blurbiz.io/blog/the-most-complete-guide-to-finding-anyones-email) - Written by [Timur Daudpota](https://www.blurbiz.io/).

<a name="dns-rebinding"></a>
### DNS Yeniden Bağlama

- [DNS Yeniden Bağlama ile İnternet Üzerinden Özel Ağlara Saldırı](https://medium.com/@brannondorsey/attacking-private-networks-from-the-internet-with-dns-rebinding-ea7098a2d325) - [@brannondorsey](https://medium.com/@brannondorsey) tarafından yazılmıştır
- [İnternet Üzerinden Ev Yönlendiricilerini Hacklemek](https://medium.com/@radekk/hackers-can-get-access-to-your-home-router-1ddadd12a7a7) - [@radekk](https://medium.com/@radekk) tarafından yazılmıştır

<a name="deserialization"></a>
### Serileştirme

- [WebLogic, WebSphere, JBoss, Jenkins, OpenNMS ve Uygulamanızın Ortak Noktası Nedir? Bu Güvenlik Açığı.](https://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/) - [@breenmachine](https://twitter.com/breenmachine) tarafından yazılmıştır.
- [.NET serileştirmesine saldırı](https://www.youtube.com/watch?v=eDfGpu3iE4Q) - [@pwntester](https://twitter.com/pwntester) tarafından yazılmıştır.
- [.NET Ruleti: Telerik UI'da Güvensiz Serileştirmeyi Sömürme](https://www.youtube.com/watch?v=--6PiuvBGAU) - [@noperator](https://twitter.com/noperator) tarafından yazılmıştır.
- [DotNetNuke Çerez Serileştirmesi Nasıl Sömürülür?](https://pentest-tools.com/blog/exploit-dotnetnuke-cookie-deserialization/) - [CRISTIAN CORNEA](https://pentest-tools.com/blog/author/pentest-cristian/) tarafından yazılmıştır.
- [LIFERAY CVE-2020-7961 NASIL SÖMÜRÜLÜR: KANIT KODUNA HIZLI YOLCULUK](https://www.synacktiv.com/en/publications/how-to-exploit-liferay-cve-2020-7961-quick-journey-to-poc.html) - [@synacktiv](https://twitter.com/synacktiv) tarafından yazılmıştır.

<a name="oauth"></a>
### OAuth

- [OAuth 2.0 ve OpenID Connect'e Giriş](https://pragmaticwebsecurity.com/courses/introduction-oauth-oidc.html) - [@PhilippeDeRyck](https://twitter.com/PhilippeDeRyck) tarafından yazılmıştır.
- [OAuth 2.0'da Neler Oluyor? Ve neden kimlik doğrulama için kullanmamalısınız?](https://medium.com/securing/what-is-going-on-with-oauth-2-0-and-why-you-should-not-use-it-for-authentication-5f47597b2611) - [@damianrusinek](https://medium.com/@damianrusinek) tarafından yazılmıştır.

<a name="jwt"></a>
### JWT

- [Sabitlenmiş sırlar, doğrulanmamış token'lar ve diğer yaygın JWT hataları](https://r2c.dev/blog/2020/hardcoded-secrets-unverified-tokens-and-other-common-jwt-mistakes/) - [@ermil0v](https://twitter.com/ermil0v) tarafından yazılmıştır.

## Atlatma Teknikleri

<a name="evasions-xxe"></a>
### XXE

- [Farklı Kodlama Kullanarak OOB XXE Düzeltmesini Atlatma](https://twitter.com/SpiderSec/status/1191375472690528256) - [@SpiderSec](https://twitter.com/SpiderSec) tarafından yazılmıştır.

<a name="evasions-csp"></a>
### İçerik Güvenlik Politikası (CSP)

- [Dinamik modül içe aktarmaya karşı herhangi bir koruma var mı?](https://github.com/w3c/webappsec-csp/issues/243) - [@shhnjk](https://twitter.com/@shhnjk) tarafından yazılmıştır.
- [CSP: Yansıtılmış XSS ile form-action'ı atlatma](https://labs.detectify.com/2016/04/04/csp-bypassing-form-action-with-reflected-xss/) - [Detectify Labs](https://labs.detectify.com/) tarafından yazılmıştır.
- [TWITTER XSS + CSP ATLATMA](http://www.paulosyibelo.com/2017/05/twitter-xss-csp-bypass.html) - [Paulos Yibelo](http://www.paulosyibelo.com/) tarafından yazılmıştır.
- [CSP'yi Zarifçe Atlatma](https://lab.wallarm.com/how-to-trick-csp-in-letting-you-run-whatever-you-want-73cb5ff428aa) - [Wallarm](https://wallarm.com/) tarafından yazılmıştır.
- [DOM tabanlı sarkan işaretleme ile CSP'den kaçınma](https://portswigger.net/blog/evading-csp-with-dom-based-dangling-markup) - [portswigger](https://portswigger.net/) tarafından yazılmıştır.
- [GitHub'ın CSP yolculuğu](https://githubengineering.com/githubs-csp-journey/) - [@ptoomey3](https://github.com/ptoomey3) tarafından yazılmıştır.
- [GitHub'ın CSP sonrası yolculuğu](https://githubengineering.com/githubs-post-csp-journey/) - [@ptoomey3](https://github.com/ptoomey3) tarafından yazılmıştır.

<a name="evasions-waf"></a>
### Web Uygulama Güvenlik Duvarı (WAF)

- [Web Uygulama Güvenlik Duvarı (WAF) Atlatma Teknikleri](https://medium.com/secjuice/waf-evasion-techniques-718026d693d8) - [@secjuice](https://twitter.com/secjuice) tarafından yazılmıştır.
- [Web Uygulama Güvenlik Duvarı (WAF) Atlatma Teknikleri #2](https://medium.com/secjuice/web-application-firewall-waf-evasion-techniques-2-125995f3e7b0) - [@secjuice](https://twitter.com/secjuice) tarafından yazılmıştır.
- [Airbnb – JSON Kodlamayı, XSS Filtresini, WAF'ı, CSP'yi ve Denetçiyi Atlatmanın Sekiz Güvenlik Açığına Dönüşmesi](https://buer.haus/2017/03/08/airbnb-when-bypassing-json-encoding-xss-filter-waf-csp-and-auditor-turns-into-eight-vulnerabilities/) - [@Brett Buerhaus](https://twitter.com/bbuerhaus) tarafından yazılmıştır.
- [Birçok WAF/NGWAF'ta libinjection'ı nasıl atlarsınız?](https://medium.com/@d0znpp/how-to-bypass-libinjection-in-many-waf-ngwaf-1e2513453c0f) - [@d0znpp](https://medium.com/@d0znpp) tarafından yazılmıştır.

<a name="evasions-jsmvc"></a>
### JavaScript MVC Çerçeveleri

- [JavaScript MVC ve Şablonlama Çerçeveleri](http://www.slideshare.net/x00mario/jsmvcomfg-to-sternly-look-at-javascript-mvc-and-templating-frameworks) - [Mario Heiderich](http://www.slideshare.net/x00mario) tarafından yazılmıştır.

<a name="evasions-authentication"></a>
### Kimlik Doğrulama

- [Trend Micro Tehdit Keşif Cihazı - Oturum Oluşturma ile Kimlik Doğrulama Atlatma (CVE-2016-8584)](http://blog.malerisch.net/2017/04/trend-micro-threat-discovery-appliance-session-generation-authentication-bypass-cve-2016-8584.html) - [@malerisch](https://twitter.com/malerisch) ve [@steventseeley](https://twitter.com/steventseeley) tarafından yazılmıştır.

## Püf Noktaları

<a name="tricks-csrf"></a>
### CSRF

- [CSRF korumasını atlatmak için zarif hileler](https://zhuanlan.zhihu.com/p/32716181) - [Twosecurity](https://twosecurity.io/) tarafından yazılmıştır.
- [Flash ve yönlendirmelerle JSON uç noktalarında CSRF'den yararlanma](https://blog.appsecco.com/exploiting-csrf-on-json-endpoints-with-flash-and-redirects-681d4ad6b31b) - [@riyazwalikar](https://blog.appsecco.com/@riyazwalikar) tarafından yazılmıştır.
- [CSS enjeksiyonu ile CSRF token'larını çalma (iFrame olmadan)](https://github.com/dxa4481/cssInjection) - [@dxa4481](https://github.com/dxa4481) tarafından yazılmıştır.
- [CSRF için Java'nın RNG'sini Kırmak - Javax Faces ve CSRF Token Rastgeleliğinin Önemi](https://blog.securityevaluators.com/cracking-javas-rng-for-csrf-ea9cacd231d2) - [@rramgattie](https://blog.securityevaluators.com/@rramgattie) tarafından yazılmıştır.
- [HttpOnly Olsa Bile Hala CSRF Yapabilirsiniz… Tabii CORS'a İzin Veriyorsa!](https://medium.com/@_graphx/if-httponly-you-could-still-csrf-of-cors-you-can-5d7ee2c7443) - [@GraphX](https://twitter.com/GraphX) tarafından yazılmıştır.

<a name="tricks-clickjacking"></a>
### Tıklama Hırsızlığı

- [Google'da 14.981,7$ Değerinde Tıklama Hırsızlıkları](https://medium.com/@raushanraj_65039/google-clickjacking-6a04132b918a) - [@raushanraj_65039](https://medium.com/@raushanraj_65039) tarafından yazılmıştır.

<a name="tricks-rce"></a>
### Uzaktan Kod Çalıştırma

- [CVE-2019-1306: BENİM İNDEKSİM MİSİN?](https://www.thezdi.com/blog/2019/10/23/cve-2019-1306-are-you-my-index) - [@yu5k3](https://twitter.com/yu5k3) tarafından yazılmıştır.
- [WebLogic Uzaktan Kod Çalıştırma (CVE-2019-2725) Hata Ayıklama Günlüğü](https://paper.seebug.org/910/) - Badcode@Knownsec 404 Ekibi tarafından yazılmıştır.
- [WebLogic, WebSphere, JBoss, Jenkins, OpenNMS ve Uygulamanızın Ortak Noktası Nedir? Bu Güvenlik Açığı.](https://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/) - [@breenmachine](https://twitter.com/@breenmachine) tarafından yazılmıştır.
- [Node.js serileştirme hatasını Uzaktan Kod Çalıştırmak için kullanma](https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/) - [OpSecX](https://opsecx.com/index.php/author/ajinabraham/) tarafından yazılmıştır.
- [DRUPAL 7.X SERVİSLER MODÜLÜ UNSERIALIZE() İLE UZAKTAN KOD ÇALIŞTIRMA](https://www.ambionics.io/blog/drupal-services-module-rce) - [Ambionics Security](https://www.ambionics.io/) tarafından yazılmıştır.
- [math.js'deki bir uzaktan kod çalıştırma güvenlik açığından nasıl yararlandık](https://capacitorset.github.io/mathjs/) - [@capacitorset](https://github.com/capacitorset) tarafından yazılmıştır.
- [GitHub Enterprise Remote Code Execution](http://exablue.de/blog/2017-03-15-github-enterprise-remote-code-execution.html) - Written by [@iblue](https://github.com/iblue).
- [Evil Teacher: Code Injection in Moodle](https://blog.ripstech.com/2018/moodle-remote-code-execution/) - Written by [RIPS Technologies](https://www.ripstech.com/).
- [How I Chained 4 vulnerabilities on GitHub Enterprise, From SSRF Execution Chain to RCE!](http://blog.orange.tw/2017/07/how-i-chained-4-vulnerabilities-on.html) - Written by [Orange](http://blog.orange.tw/).
- [$36k Google App Engine RCE](https://sites.google.com/site/testsitehacking/-36k-google-app-engine-rce) - Written by [Ezequiel Pereira](https://sites.google.com/site/testsitehacking/).
- [Poor RichFaces](https://codewhitesec.blogspot.com/2018/05/poor-richfaces.html) - Written by [CODE WHITE](https://www.code-white.com/).
- [Remote Code Execution on a Facebook server](https://blog.scrt.ch/2018/08/24/remote-code-execution-on-a-facebook-server/) - Written by [@blaklis_](https://twitter.com/blaklis_).

<a name="tricks-xss"></a>
### XSS

- [20 karakter sınırı ile XSS'den yararlanma](https://jlajara.gitlab.io/posts/2019/11/30/XSS_20_characters.html) - [Jorge Lajara](https://jlajara.gitlab.io/) tarafından yazılmıştır.
- [Self XSS'i Sömürülebilir XSS'e Yükseltme - 3 Yöntem Tekniği](https://www.hahwul.com/2019/11/upgrade-self-xss-to-exploitable-xss.html) - [HAHWUL](https://www.hahwul.com/) tarafından yazılmıştır.
- [Parantez ve noktalı virgül olmadan XSS](https://portswigger.net/blog/xss-without-parentheses-and-semi-colons) - [@garethheyes](https://twitter.com/garethheyes) tarafından yazılmıştır.
- [XSS-Denetçisi - korunmasızların koruyucusu ve korunanların aldatıcısı](https://medium.com/bugbountywriteup/xss-auditor-the-protector-of-unprotected-f900a5e15b7b) - [@terjanq](https://medium.com/@terjanq) tarafından yazılmıştır.
- [Sorgu parametrelerinin yeniden sıralanması, yönlendirme sayfasının güvensiz URL göstermesine neden oluyor](https://hackerone.com/reports/293689) - [kenziy](https://hackerone.com/kenziy) tarafından yazılmıştır.
- [Saldırganın Perspektifinden ECMAScript 6 - Çerçeveleri, Kum Havuzlarını ve Diğer Her Şeyi Kırmak](http://www.slideshare.net/x00mario/es6-en) - [Mario Heiderich](http://www.slideshare.net/x00mario) tarafından yazılmıştır.
- [Protobuf ile Uğraşarak 5.000$'lık Google Maps XSS'sini Nasıl Buldum?](https://medium.com/@marin_m/how-i-found-a-5-000-google-maps-xss-by-fiddling-with-protobuf-963ee0d9caff) - [@marin_m](https://medium.com/@marin_m) tarafından yazılmıştır.
- [DOM'A GÜVENMEYİN: BETİK ARAÇLARI İLE XSS AZALTMA TEKNİKLERİNİ ATLATMA](https://www.blackhat.com/docs/us-17/thursday/us-17-Lekies-Dont-Trust-The-DOM-Bypassing-XSS-Mitigations-Via-Script-Gadgets.pdf) - [Sebastian Lekies](https://twitter.com/slekies), [Krzysztof Kotowicz](https://twitter.com/kkotowicz) ve [Eduardo Vela](https://twitter.com/sirdarckcat) tarafından yazılmıştır.
- [Çerez Üzerinden Uber'da XSS](http://zhchbin.github.io/2017/08/30/Uber-XSS-via-Cookie/) - [zhchbin](http://zhchbin.github.io/) tarafından yazılmıştır.
- [DOM XSS – auth.uber.com](http://stamone-bug-bounty.blogspot.tw/2017/10/dom-xss-auth14.html) - [StamOne_](http://stamone-bug-bounty.blogspot.tw/) tarafından yazılmıştır.
- [Facebook'ta Depolanmış XSS](https://opnsec.com/2018/03/stored-xss-on-facebook/) - [Enguerran Gillier](https://opnsec.com/) tarafından yazılmıştır.
- [Google Colaboratory'de XSS + CSP Atlatma](https://blog.bentkowski.info/2018/06/xss-in-google-colaboratory-csp-bypass.html) - [Michał Bentkowski](https://blog.bentkowski.info/) tarafından yazılmıştır.
- [Google Colaboratory'de Başka Bir XSS](https://blog.bentkowski.info/2018/09/another-xss-in-google-colaboratory.html) - [Michał Bentkowski](https://blog.bentkowski.info/) tarafından yazılmıştır.
- [</script> Filtrelenmiş mi?](https://twitter.com/strukt93/status/931586377665331200) - [@strukt93](https://twitter.com/strukt93) tarafından yazılmıştır.
- [20.000$'lık Facebook DOM XSS'i](https://vinothkumar.me/20000-facebook-dom-xss/) - [@vinodsparrow](https://twitter.com/vinodsparrow) tarafından yazılmıştır.

<a name="tricks-sql-injection"></a>
### SQL Enjeksiyonu

- [EXP Kullanarak MySQL Hata Tabanlı SQL Enjeksiyonu](https://www.exploit-db.com/docs/english/37953-mysql-error-based-sql-injection-using-exp.pdf) - [@osandamalith](https://twitter.com/osandamalith) tarafından yazılmıştır.
- [UPDATE sorgusunda SQL enjeksiyonu - bir bug bounty hikayesi!](http://zombiehelp54.blogspot.jp/2017/02/sql-injection-in-update-query-bug.html) - [Zombiehelp54](http://zombiehelp54.blogspot.jp/) tarafından yazılmıştır.
- [GitHub Enterprise SQL Enjeksiyonu](http://blog.orange.tw/2017/01/bug-bounty-github-enterprise-sql-injection.html) - [Orange](http://blog.orange.tw/) tarafından yazılmıştır.
- [Kör SQL Enjeksiyonunu Biraz Daha Az Kör Yapmak](https://medium.com/@tomnomnom/making-a-blind-sql-injection-a-little-less-blind-428dcb614ba8) - [TomNomNom](https://twitter.com/TomNomNom) tarafından yazılmıştır.
- [Kırmızı Takım Hikayeleri 0x01: MSSQL'den RCE'ye](https://www.tarlogic.com/en/blog/red-team-tales-0x01/) - [Tarlogic](https://www.tarlogic.com/en/cybersecurity-blog/) tarafından yazılmıştır.
- [SQL ENJEKSİYONU VE POSTGRES - SONUNDA RCE'YE UZANAN BİR MACERA](https://pulsesecurity.co.nz/articles/postgres-sqli) - [@denandz](https://github.com/denandz) tarafından yazılmıştır.

<a name="tricks-nosql-injection"></a>
### NoSQL Enjeksiyonu

- [JSON Tipleri Aracılığıyla GraphQL NoSQL Enjeksiyonu](http://www.petecorey.com/blog/2017/06/12/graphql-nosql-injection-through-json-types/) - [Pete](http://www.petecorey.com/work/) tarafından yazılmıştır.

<a name="tricks-ftp-injection"></a>
### FTP Enjeksiyonu

- [XML Bant Dışı Veri Çekme](https://media.blackhat.com/eu-13/briefings/Osipov/bh-eu-13-XML-data-osipov-slides.pdf) - [@a66at](https://twitter.com/a66at) ve Alexey Osipov tarafından yazılmıştır.
- [Java 1.7+ Üzerinde XXE OOB Sömürüsü](http://lab.onsec.ru/2014/06/xxe-oob-exploitation-at-java-17.html) - [Ivan Novikov](http://lab.onsec.ru/) tarafından yazılmıştır.

<a name="tricks-xxe"></a>
### XXE (XML Harici Varlık Saldırısı)

- [İki Kodlamalı Kötü Amaçlı XML](https://mohemiv.com/all/evil-xml/) - [Arseniy Sharoglazov](https://mohemiv.com/) tarafından yazılmıştır.
- [WeChat Pay SDK'sında XXE (WeChat satıcı web sitelerinde arka kapı bırakıyor)](http://seclists.org/fulldisclosure/2018/Jul/3) - [Rose Jackcode](https://twitter.com/codeshtool) tarafından yazılmıştır.
- [XML Bant Dışı Veri Çekme](https://media.blackhat.com/eu-13/briefings/Osipov/bh-eu-13-XML-data-osipov-slides.pdf) - Timur Yunusov ve Alexey Osipov tarafından yazılmıştır.
- [Java 1.7+ Üzerinde XXE OOB Sömürüsü (2014)](http://lab.onsec.ru/2014/06/xxe-oob-exploitation-at-java-17.html): FTP protokolü kullanarak veri sızıntısı - [Ivan Novikov](https://twitter.com/d0znpp/) tarafından yazılmıştır.
- [Tek Açık Port Üzerinden HTTP+FTP ile XXE OOB Veri Çıkarma](https://skavans.ru/en/2017/12/02/xxe-oob-extracting-via-httpftp-using-single-opened-port/) - [skavans](https://skavans.ru/) tarafından yazılmıştır.
- [XML Harici Varlık Saldırıları Hakkında Bilmedikleriniz](https://2013.appsecusa.org/2013/wp-content/uploads/2013/12/WhatYouDidntKnowAboutXXEAttacks.pdf) - [Timothy D. Morgan](https://twitter.com/ecbftw) tarafından yazılmıştır.
- [Drupal Services Modülünde Kimlik Doğrulama Öncesi XXE Açığı](https://www.synacktiv.com/ressources/synacktiv_drupal_xxe_services.pdf) - [Renaud Dubourguais](https://twitter.com/_m0bius) tarafından yazılmıştır.
- [Sunucu Hata Mesajları Üzerinden XXE Yansıtma Zorlama](https://blog.netspi.com/forcing-xxe-reflection-server-error-messages/) - [Antti Rantasaari](https://blog.netspi.com/author/antti-rantasaari/) tarafından yazılmıştır.
- [Yerel DTD Dosyaları ile XXE'den Yararlanma](https://mohemiv.com/all/exploiting-xxe-with-local-dtd-files/) - [Arseniy Sharoglazov](https://twitter.com/_mohemiv) tarafından yazılmıştır.
- [XXE Sömürüsü İçin Yerel DTD Keşfini Otomatikleştirme](https://www.gosecure.net/blog/2019/07/16/automating-local-dtd-discovery-for-xxe-exploitation) - [Philippe Arteau](https://twitter.com/h3xstream) tarafından yazılmıştır.

<a name="tricks-ssrf"></a>
### SSRF (Sunucu Taraflı İstek Sahteciliği)

- [JavaScript'te SSRF ile AWS Ele Geçirme](http://10degres.net/aws-takeover-through-ssrf-in-javascript/) - [Gwen](http://10degres.net/) tarafından yazılmıştır.
- [Exchange'deki SSRF, Tüm Örneklerde KÖK Erişimine Yol Açıyor](https://hackerone.com/reports/341876) - [@0xacb](https://twitter.com/0xacb) tarafından yazılmıştır.
- [SSRF'den KÖK Erişimine](https://hackerone.com/reports/341876) - Tüm örneklerde KÖK Erişimine yol açan SSRF için 25.000$'lık ödül - [0xacb](https://hackerone.com/0xacb) tarafından yazılmıştır.
- [PHP SSRF Teknikleri](https://medium.com/secjuice/php-ssrf-techniques-9d422cb28d51) - [@themiddleblue](https://medium.com/@themiddleblue) tarafından yazılmıştır.
- [https://imgur.com/vidgif/url Adresinde SSRF](https://hackerone.com/reports/115748) - [aesteral](https://hackerone.com/aesteral) tarafından yazılmıştır.
- [SSRF Hakkında Bilmeniz Gereken Her Şey ve Otomatik Tespit İçin Araçlar Nasıl Yazılır?](https://www.auxy.xyz/web%20security/2017/07/06/all-ssrf-knowledge.html) - [@Auxy233](https://twitter.com/Auxy233) tarafından yazılmıştır.
- [SSRF'de Yeni Bir Çağ - Popüler Programlama Dillerinde URL Ayrıştırıcıyı Sömürme!](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf) - [Orange](http://blog.orange.tw/) tarafından yazılmıştır.
- [SSRF İpuçları](http://blog.safebuff.com/2016/07/03/SSRF-Tips/) - [xl7dev](http://blog.safebuff.com/) tarafından yazılmıştır.
- [Borg'un İçinde – Google üretim ağında SSRF](https://opnsec.com/2018/07/into-the-borg-ssrf-inside-google-production-network/) - [opnsec](https://opnsec.com/) tarafından yazılmıştır.
- [Örtüyü Delmek: NIPRNet Erişimine Sunucu Taraflı İstek Sahteciliği](https://medium.com/bugbountywriteup/piercing-the-veil-server-side-request-forgery-to-niprnet-access-c358fd5e249a) - [Alyssa Herrera](https://medium.com/@alyssa.o.herrera) tarafından yazılmıştır.

<a name="tricks-web-cache-poisoning"></a>
### Web Önbellek Zehirleme

- [Web Önbellek Zehirleme Önlemlerini Atlatma](https://portswigger.net/blog/bypassing-web-cache-poisoning-countermeasures) - [@albinowax](https://twitter.com/albinowax) tarafından yazılmıştır.
- [Önbellek zehirleme ve diğer kirli numaralar](https://lab.wallarm.com/cache-poisoning-and-other-dirty-tricks-120468f1053f) - [Wallarm](https://wallarm.com/) tarafından yazılmıştır.

<a name="tricks-header-injection"></a>
### Başlık Enjeksiyonu

- [Java/Python FTP Enjeksiyonları Güvenlik Duvarını Atlatmayı Mümkün Kılıyor](http://blog.blindspotsecurity.com/2017/02/advisory-javapython-ftp-injections.html) - [Timothy Morgan](https://plus.google.com/105917618099766831589) tarafından yazılmıştır.

<a name="tricks-url"></a>
### URL

- [URL'lerin Bazı Sorunları](https://noncombatant.org/2017/11/07/problems-of-urls/) - [Chris Palmer](https://noncombatant.org/about/) tarafından yazılmıştır.
- [Unicode Alan Adları ile Kimlik Avı](https://www.xudongz.com/blog/2017/idn-phishing/) - [Xudong Zheng](https://www.xudongz.com/) tarafından yazılmıştır.
- [Unicode Alan Adları Kötüdür ve Onları Desteklediğiniz İçin Kötü Hissetmelisiniz](https://www.vgrsec.com/post20170219.html) - [VRGSEC](https://www.vgrsec.com/) tarafından yazılmıştır.
- [[dev.twitter.com] XSS](http://blog.blackfan.ru/2017/09/devtwittercom-xss.html) - [Sergey Bobrov](http://blog.blackfan.ru/) tarafından yazılmıştır.

<a name="tricks-deserialization"></a>
### Serileştirme

- [ASP.NET kaynak dosyaları (.RESX) ve serileştirme sorunları](https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2018/august/aspnet-resource-files-resx-and-deserialisation-issues/) - [@irsdl](https://twitter.com/irsdl) tarafından yazılmıştır.

<a name="tricks-oauth"></a>
### OAuth

- [Facebook OAuth Çerçeve Güvenlik Açığı](https://www.amolbaikar.com/facebook-oauth-framework-vulnerability/) - [@AmolBaikar](https://twitter.com/AmolBaikar) tarafından yazılmıştır.

<a name="tricks-others"></a>
### Diğerleri

- [Google'ın hata takip sistemini 15.600$ ödül için nasıl hackledim?](https://medium.com/free-code-camp/messing-with-the-google-buganizer-system-for-15-600-in-bounties-58f86cc9f9a5) - [@alex.birsan](https://medium.com/@alex.birsan) tarafından yazılmıştır.
- [Gizli Grubumdan Bazı Püf Noktaları](https://www.leavesongs.com/SHARE/some-tricks-from-my-secret-group.html) - [phithon](https://www.leavesongs.com/) tarafından yazılmıştır.
- [Onion Web Hizmetlerinde DNS Sızıntılarını Tetikleme](https://github.com/epidemics-scepticism/writing/blob/master/onion-dns-leaks.md) - [@epidemics-scepticism](https://github.com/epidemics-scepticism) tarafından yazılmıştır.
- [Veri Kümesi Yayınlama Dili Kullanarak Google'da Depolanmış XSS ve SSRF](https://s1gnalcha0s.github.io/dspl/2018/03/07/Stored-XSS-and-SSRF-Google.html) - [@signalchaos](https://twitter.com/signalchaos) tarafından yazılmıştır.

## Tarayıcı Sömürüsü

### Ön Yüz (SOP atlatma, URL sahteciliği ve benzeri)

- [Site İzolasyonu ve Ele Geçirilmiş Oluşturucu Dünyası](https://speakerdeck.com/shhnjk/the-world-of-site-isolation-and-compromised-renderer) - [@shhnjk](https://twitter.com/shhnjk) tarafından yazılmıştır.
- [Tarayıcılarınızdaki Çerez Canavarı](https://speakerdeck.com/filedescriptor/the-cookie-monster-in-your-browsers) - [@filedescriptor](https://twitter.com/filedescriptor) tarafından yazılmıştır.
- [Eğlence ve Kar İçin Mobil Tarayıcı Güvenliğini Atlatma](https://www.blackhat.com/docs/asia-16/materials/asia-16-Baloch-Bypassing-Browser-Security-Policies-For-Fun-And-Profit-wp.pdf) - [@rafaybaloch](https://twitter.com/rafaybaloch) tarafından yazılmıştır.
- [Başlangıç çubuğu: Yeni bir kimlik avı yöntemi](https://jameshfisher.com/2019/04/27/the-inception-bar-a-new-phishing-method/) - [jameshfisher](https://jameshfisher.com/) tarafından yazılmıştır.
- [Modern web için JSON ele geçirme](http://blog.portswigger.net/2016/11/json-hijacking-for-modern-web.html) - [portswigger](https://portswigger.net/) tarafından yazılmıştır.
- [IE11 Bilgi Sızıntısı - Yerel dosya tespiti](https://www.facebook.com/ExploitWareLabs/photos/a.361854183878462.84544.338832389513975/1378579648872572/?type=3&theater) - James Lee tarafından yazılmıştır.
- [SOP atlatma / UXSS - Kimlik Bilgilerini Oldukça Hızlı Çalma (Edge)](https://www.brokenbrowser.com/sop-bypass-uxss-stealing-credentials-pretty-fast/) - [Manuel](https://twitter.com/magicmac2000) tarafından yazılmıştır.
- [İstemci Taraflı Saldırılarda Safari'nin Özellikleri](https://bo0om.ru/safari-client-side) - [Bo0oM](https://bo0om.ru/author/admin) tarafından yazılmıştır.
- [Çekirdekler Arasında Bilgi Sızıntısını Nasıl Durdururuz?](https://docs.google.com/document/d/1cbL-X0kV_tQ5rL8XJ3lXkV-j0pt_CfTu5ZSzYrncPDc/) - [aaj@google.com](aaj@google.com) ve [mkwst@google.com](mkwst@google.com) tarafından yazılmıştır.
- [CRLF enjeksiyonu ile Chromium'da keyfi istek başlıkları ayarlama](https://blog.bentkowski.info/2018/06/setting-arbitrary-request-headers-in.html) - [Michał Bentkowski](https://blog.bentkowski.info/) tarafından yazılmıştır.
- [Sitenizden kredi kartı numaralarını ve şifreleri topluyorum. İşte nasıl.](https://hackernoon.com/im-harvesting-credit-card-numbers-and-passwords-from-your-site-here-s-how-9a8cb347c5b5) - [David Gilbertson](https://hackernoon.com/@david.gilbertson) tarafından yazılmıştır.
- [Function.prototype.apply'ı geçersiz kılarak keyfi IPC mesajları gönderme](https://hackerone.com/reports/188086) - [@kinugawamasato](https://twitter.com/kinugawamasato) tarafından yazılmıştır.
- [Bug Ödül Programlarında Kapsam Dışı Alanlardan Yararlanın](https://ahussam.me/Take-Advantage-of-Out-of-Scope-Domains-in-Bug-Bounty/) - [@Abdulahhusam](https://twitter.com/Abdulahhusam) tarafından yazılmıştır.

### Arka Uç (Tarayıcı uygulamasının çekirdeği ve genellikle C veya C++ kısmını ifade eder)

- [UC Tarayıcıyı Kırma](https://habr.com/en/company/drweb/blog/452076/) - [Доктор Веб](https://www.drweb.ru/) tarafından yazılmıştır.
- [JavaScript Motorlarına Saldırı - JavaScriptCore ve CVE-2016-4622 Vaka Çalışması](http://www.phrack.org/papers/attacking_javascript_engines.html) - [phrack@saelo.net](phrack@saelo.net) tarafından yazılmıştır.
- [Üç Yol Roma'ya Çıkar](http://blogs.360.cn/360safe/2016/11/29/three-roads-lead-to-rome-2/) - [@holynop](https://twitter.com/holynop) tarafından yazılmıştır.
- [V8'de Sınır Dışı Yazma Açığından Yararlanma](https://halbecaf.com/2017/05/24/exploiting-a-v8-oob-write/) - [@halbecaf](https://twitter.com/halbecaf) tarafından yazılmıştır.
- [SSD Danışmanlık - Chrome Turbofan Uzaktan Kod Çalıştırma](https://blogs.securiteam.com/index.php/archives/3379) - [SecuriTeam Secure Disclosure (SSD)](https://blogs.securiteam.com/) tarafından yazılmıştır.
- [Bak Anne, Shellcode Kullanmıyorum - Internet Explorer 11 İçin Tarayıcı Sömürüsü Vaka Çalışması](https://labs.bluefrostsecurity.de/files/Look_Mom_I_Dont_Use_Shellcode-WP.pdf) - [@moritzj](http://twitter.com/moritzj) tarafından yazılmıştır.
- [BİR MOBİL PWN2OWN ZAFİYETİ İLE WEBKIT'İN DÜĞMELERİNE BASMAK](https://www.zerodayinitiative.com/blog/2018/2/12/pushing-webkits-buttons-with-a-mobile-pwn2own-exploit) - [@wanderingglitch](https://twitter.com/wanderingglitch) tarafından yazılmıştır.
- [Tarayıcı Sömürüsüne Yöntemsel Bir Yaklaşım](https://blog.ret2.io/2018/06/05/pwn2own-2018-exploit-development/) - [RET2 SYSTEMS, INC](https://blog.ret2.io/) tarafından yazılmıştır.
- [CVE-2017-2446 veya JSC::JSGlobalObject::isHavingABadTime](https://doar-e.github.io/blog/2018/07/14/cve-2017-2446-or-jscjsglobalobjectishavingabadtime/) - [Tersine Mühendislik Günlüğü](https://doar-e.github.io/) tarafından yazılmıştır.
- [CHROME KUM HAVUZUNDAN TEMİZCE KAÇIŞ](https://theori.io/research/escaping-chrome-sandbox) - [@tjbecker_](https://twitter.com/tjbecker_) tarafından yazılmıştır.
- [Tarayıcı Sömürüsüne Yöntemsel Bir Yaklaşım](https://blog.ret2.io/2018/06/05/pwn2own-2018-exploit-development/) - [@PatrickBiernat](https://twitter.com/PatrickBiernat), [@gaasedelen](https://twitter.com/gaasedelen) ve [@itszn13](https://twitter.com/itszn13) tarafından yazılmıştır.

## Zafiyet Kanıtları (PoC'lar)

<a name="pocs-database"></a>
### Veritabanları

- [js-vuln-db](https://github.com/tunz/js-vuln-db) - PoC'larıyla birlikte JavaScript motoru CVE'leri koleksiyonu - [@tunz](https://github.com/tunz) tarafından derlenmiştir.
- [awesome-cve-poc](https://github.com/qazbnm456/awesome-cve-poc) - Seçilmiş CVE PoC'ları listesi - [@qazbnm456](https://github.com/qazbnm456) tarafından derlenmiştir.
- [Some-PoC-oR-ExP](https://github.com/coffeehb/Some-PoC-oR-ExP) - Çeşitli zafiyet PoC'ları ve Exploit'lerin toplanması veya yazılması - [@coffeehb](https://github.com/coffeehb) tarafından derlenmiştir.
- [uxss-db](https://github.com/Metnew/uxss-db) - PoC'larıyla birlikte UXSS CVE'leri koleksiyonu - [@Metnew](https://github.com/Metnew) tarafından derlenmiştir.
- [SPLOITUS](https://sploitus.com/) - Exploit ve Araç Arama Motoru - [@i_bo0om](https://twitter.com/i_bo0om) tarafından geliştirilmiştir.
- [Exploit Veritabanı](https://www.exploit-db.com/) - Exploit'ler, Shellcode ve Güvenlik Makalelerinin nihai arşivi - [Offensive Security](https://www.offensive-security.com/) tarafından yönetilmektedir.

## Kılavuzlar

- [XSS Kılavuzu - 2018 Sürümü](https://leanpub.com/xss) - [@brutelogic](https://twitter.com/brutelogic) tarafından yazılmıştır.
- [Bayrak Kapma (CTF) Kılavuzu](https://github.com/uppusaikiran/awesome-ctf-cheatsheet) - [@uppusaikiran](https://github.com/uppusaikiran) tarafından derlenmiştir.

## Araçlar

<a name="tools-auditing"></a>
### Denetim

- [prowler](https://github.com/Alfresco/prowler) - AWS güvenlik değerlendirmesi, denetimi ve güçlendirmesi için araç - [@Alfresco](https://github.com/Alfresco) tarafından geliştirilmiştir.
- [slurp](https://github.com/hehnope/slurp) - S3 kovalarının güvenliğini değerlendirme aracı - [@hehnope](https://github.com/hehnope) tarafından geliştirilmiştir.
- [A2SV](https://github.com/hahwul/a2sv) - SSL Güvenlik Açıkları için Otomatik Tarama Aracı - [@hahwul](https://github.com/hahwul) tarafından geliştirilmiştir.

<a name="tools-command-injection"></a>
### Komut Enjeksiyonu

- [commix](https://github.com/commixproject/commix) - Tümü Bir Arada Otomatik İşletim Sistemi Komut Enjeksiyon ve Sömürü Aracı - [@commixproject](https://github.com/commixproject) tarafından geliştirilmiştir.

<a name="tools-reconnaissance"></a>
### Keşif

<a name="tools-osint"></a>
#### OSINT - Açık Kaynak İstihbaratı

- [Shodan](https://www.shodan.io/) - İnternete bağlı cihazlar için dünyanın ilk arama motoru - [@shodanhq](https://twitter.com/shodanhq) tarafından geliştirilmiştir.
- [Censys](https://censys.io/) - Bilgisayar bilimcilerinin İnternet'i oluşturan cihazlar ve ağlar hakkında soru sormasına olanak tanıyan bir arama motoru - [Michigan Üniversitesi](https://umich.edu/) tarafından geliştirilmiştir.
- [urlscan.io](https://urlscan.io/) - Web sitelerini ve talep ettikleri kaynakları analiz eden hizmet - [@heipei](https://twitter.com/heipei) tarafından geliştirilmiştir.
- [ZoomEye](https://www.zoomeye.org/) - Siber Uzay Arama Motoru - [@zoomeye_team](https://twitter.com/zoomeye_team) tarafından geliştirilmiştir.
- [FOFA](https://fofa.so/?locale=en) - Siber Uzay Arama Motoru - [BAIMAOHUI](http://baimaohui.net/) tarafından geliştirilmiştir.
- [NSFOCUS](https://nti.nsfocus.com/) - TEHDİT İSTİHBARAT PORTALI - NSFOCUS GLOBAL tarafından sunulmaktadır.
- [Photon](https://github.com/s0md3v/Photon) - OSINT için tasarlanmış inanılmaz hızlı tarayıcı - [@s0md3v](https://github.com/s0md3v) tarafından geliştirilmiştir.
- [FOCA](https://github.com/ElevenPaths/FOCA) - FOCA (Toplanan Arşivlerle Kurum Parmak İzi Çıkarma), taradığı belgelerde meta verileri ve gizli bilgileri bulmak için kullanılan bir araçtır - [ElevenPaths](https://www.elevenpaths.com/index.html) tarafından geliştirilmiştir.
- [SpiderFoot](http://www.spiderfoot.net/) - Açık kaynaklı iz sürme ve istihbarat toplama aracı - [@binarypool](https://twitter.com/binarypool) tarafından geliştirilmiştir.
- [xray](https://github.com/evilsocket/xray) - XRay, kamu ağlarından keşif, haritalama ve OSINT toplama aracıdır - [@evilsocket](https://github.com/evilsocket) tarafından geliştirilmiştir.
- [gitrob](https://github.com/michenriksen/Gitrob) - GitHub organizasyonları için keşif aracı - [@michenriksen](https://github.com/michenriksen) tarafından geliştirilmiştir.
- [GSIL](https://github.com/FeeiCN/GSIL) - GitHub Hassas Bilgi Sızıntısı - [@FeeiCN](https://github.com/FeeiCN) tarafından geliştirilmiştir.
- [raven](https://github.com/0x09AL/raven) - Raven, pentester'ların bir kuruluşun çalışanları hakkında Linkedin üzerinden bilgi toplamak için kullanabileceği bir Linkedin bilgi toplama aracıdır - [@0x09AL](https://github.com/0x09AL) tarafından geliştirilmiştir.
- [ReconDog](https://github.com/s0md3v/ReconDog) - Keşif için İsviçre Çakısı - [@s0md3v](https://github.com/s0md3v) tarafından geliştirilmiştir.
- [Veritabanları - start.me](https://start.me/p/QRENnO/databases) - OSINT araştırmalarınız için kullanabileceğiniz çeşitli veritabanları - [@technisette](https://twitter.com/technisette) tarafından derlenmiştir.
- [peoplefindThor](https://peoplefindthor.dk/) - Facebook'ta insanları bulmanın kolay yolu - [postkassen](mailto:postkassen@oejvind.dk?subject=peoplefindthor.dk yorumları) tarafından geliştirilmiştir.
- [tinfoleak](https://github.com/vaguileradiaz/tinfoleak) - Twitter istihbarat analizi için en kapsamlı açık kaynaklı araç - [@vaguileradiaz](https://github.com/vaguileradiaz) tarafından geliştirilmiştir.
- [Raccoon](https://github.com/evyatarmeged/Raccoon) - Keşif ve güvenlik açığı taraması için yüksek performanslı ofansif güvenlik aracı - [@evyatarmeged](https://github.com/evyatarmeged) tarafından geliştirilmiştir.
- [Social Mapper](https://github.com/SpiderLabs/social_mapper) - Sosyal Medya Numaralandırma ve İlişkilendirme Aracı - Jacob Wilkin (Greenwolf) tarafından [@SpiderLabs](https://github.com/SpiderLabs) için geliştirilmiştir.
- [espi0n/Dockerfiles](https://github.com/espi0n/Dockerfiles) - Çeşitli OSINT araçları için Docker dosyaları - [@espi0n](https://github.com/espi0n) tarafından derlenmiştir.

<a name="tools-sub-domain-enumeration"></a>
#### Alt Alan Adı Numaralandırma

- [Sublist3r](https://github.com/aboul3la/Sublist3r) - Sublist3r, penetrasyon testçileri için çok iş parçacıklı alt alan adı numaralandırma aracıdır - [@aboul3la](https://github.com/aboul3la) tarafından geliştirilmiştir.
- [EyeWitness](https://github.com/ChrisTruncer/EyeWitness) - EyeWitness, web sitelerinin ekran görüntülerini almak, sunucu başlık bilgilerini sağlamak ve mümkünse varsayılan kimlik bilgilerini tanımlamak için tasarlanmıştır - [@ChrisTruncer](https://github.com/ChrisTruncer) tarafından geliştirilmiştir.
- [subDomainsBrute](https://github.com/lijiejie/subDomainsBrute) - Pentester'lar için basit ve hızlı alt alan adı kaba kuvvet aracı - [@lijiejie](https://github.com/lijiejie) tarafından geliştirilmiştir.
- [AQUATONE](https://github.com/michenriksen/aquatone) - Alan Adı Keşif Aracı - [@michenriksen](https://github.com/michenriksen) tarafından geliştirilmiştir.
- [domain_analyzer](https://github.com/eldraco/domain_analyzer) - Mümkün olan tüm bilgileri bularak herhangi bir alan adının güvenliğini analiz edin - [@eldraco](https://github.com/eldraco) tarafından geliştirilmiştir.
- [VirusTotal alan adı bilgisi](https://www.virustotal.com/en/documentation/searching/#getting-domain-information) - Alan adı bilgilerini arayın - [VirusTotal](https://www.virustotal.com/) tarafından sunulmaktadır.
- [Sertifika Şeffaflığı](https://github.com/google/certificate-transparency) - Google'ın Sertifika Şeffaflığı projesi, SSL sertifika sistemindeki çeşitli yapısal kusurları düzeltir - [@google](https://github.com/google) tarafından geliştirilmiştir.
- [Sertifika Arama](https://crt.sh/) - Bir Kimlik (Alan Adı, Kuruluş Adı, vb.), Sertifika Parmak İzi (SHA-1 veya SHA-256) veya crt.sh Kimliği girerek sertifika(lar) arayın - [@crtsh](https://github.com/crtsh) tarafından sunulmaktadır.
- [GSDF](https://github.com/We5ter/GSDF) - GoogleSSLdomainFinder adlı alan adı arama aracı - [@We5ter](https://github.com/We5ter) tarafından geliştirilmiştir.

<a name="tools-code-generating"></a>
### Kod Üretme

- [VWGen](https://github.com/qazbnm456/VWGen) - Güvenlik Açıklı Web Uygulamaları Üreticisi - [@qazbnm456](https://github.com/qazbnm456) tarafından geliştirilmiştir.

<a name="tools-fuzzing"></a>
### Bulanıklaştırma (Fuzzing)

- [wfuzz](https://github.com/xmendez/wfuzz) - Web uygulaması kaba kuvvet aracı - [@xmendez](https://github.com/xmendez) tarafından geliştirilmiştir.
- [charsetinspect](https://github.com/hack-all-the-things/charsetinspect) - Belirli kullanıcı tanımlı özelliklere sahip karakterleri arayan çok baytlı karakter kümelerini inceleyen betik - [@hack-all-the-things](https://github.com/hack-all-the-things) tarafından geliştirilmiştir.
- [IPObfuscator](https://github.com/OsandaMalith/IPObfuscator) - IP'yi DWORD IP'ye dönüştüren basit bir araç - [@OsandaMalith](https://github.com/OsandaMalith) tarafından geliştirilmiştir.
- [domato](https://github.com/google/domato) - DOM bulanıklaştırıcısı - [@google](https://github.com/google) tarafından geliştirilmiştir.
- [FuzzDB](https://github.com/fuzzdb-project/fuzzdb) - Kara kutu uygulama hata enjeksiyonu ve kaynak keşfi için saldırı desenleri ve ilkelleri sözlüğü.
- [dirhunt](https://github.com/Nekmo/dirhunt) - Bir sitenin dizin yapısını aramak ve analiz etmek için optimize edilmiş web tarayıcısı - [@nekmo](https://github.com/Nekmo) tarafından geliştirilmiştir.
- [ssltest](https://www.ssllabs.com/ssltest/) - İnternet üzerindeki herhangi bir SSL web sunucusunun yapılandırmasını derinlemesine analiz eden çevrimiçi hizmet. [Qualys SSL Labs](https://www.ssllabs.com) tarafından sağlanmaktadır.
- [fuzz.txt](https://github.com/Bo0oM/fuzz.txt) - Potansiyel olarak tehlikeli dosyalar - [@Bo0oM](https://github.com/Bo0oM) tarafından derlenmiştir.

<a name="tools-scanning"></a>
### Tarama

- [wpscan](https://github.com/wpscanteam/wpscan) - WPScan, WordPress güvenlik açığı tarayıcısıdır - [@wpscanteam](https://github.com/wpscanteam) tarafından geliştirilmiştir.
- [JoomlaScan](https://github.com/drego85/JoomlaScan) - Joomla CMS'de yüklü bileşenleri bulmak için ücretsiz yazılım, Joomscan'ın küllerinden doğmuştur - [@drego85](https://github.com/drego85) tarafından geliştirilmiştir.
- [WAScan](https://github.com/m4ll0k/WAScan) - "Kara kutu" yöntemini kullanan açık kaynaklı bir web uygulama güvenlik tarayıcısıdır - [@m4ll0k](https://github.com/m4ll0k) tarafından oluşturulmuştur.
- [Nuclei](https://github.com/projectdiscovery/nuclei) - Nuclei, büyük ölçüde genişletilebilirlik ve kullanım kolaylığı sunan şablonlara dayalı yapılandırılabilir hedefli tarama için hızlı bir araçtır - [@projectdiscovery](https://github.com/projectdiscovery) tarafından geliştirilmiştir.

<a name="tools-penetration-testing"></a>
### Sızma Testi

- [Burp Suite](https://portswigger.net/burp/) - Burp Suite, web uygulamalarının güvenlik testlerini gerçekleştirmek için entegre bir platformdur - [portswigger](https://portswigger.net/) tarafından geliştirilmiştir.
- [TIDoS-Framework](https://github.com/theInfectedDrake/TIDoS-Framework) - Keşif ve OSINT'ten Güvenlik Açığı Analizine kadar her şeyi kapsayan kapsamlı bir web uygulama denetim çerçevesi - [@_tID](https://github.com/theInfectedDrake) tarafından geliştirilmiştir.
- [Astra](https://github.com/flipkart-incubator/astra) - REST API'leri için Otomatik Güvenlik Testi - [@flipkart-incubator](https://github.com/flipkart-incubator) tarafından geliştirilmiştir.
- [aws_pwn](https://github.com/dagrz/aws_pwn) - AWS penetrasyon testi için çeşitli araçlar koleksiyonu - [@dagrz](https://github.com/dagrz) tarafından derlenmiştir.
- [grayhatwarfare](https://buckets.grayhatwarfare.com/) - Halka açık depolama alanları - [grayhatwarfare](http://www.grayhatwarfare.com/) tarafından sunulmaktadır.

<a name="tools-offensive"></a>
### Ofansif Araçlar

<a name="tools-xss"></a>
#### XSS - Siteler Arası Komut Çalıştırma

- [beef](https://github.com/beefproject/beef) - Tarayıcı Sömürü Çerçeve Projesi - [beefproject](https://beefproject.com) tarafından geliştirilmiştir.
- [JShell](https://github.com/s0md3v/JShell) - XSS ile JavaScript kabuğu elde etme aracı - [@s0md3v](https://github.com/s0md3v) tarafından geliştirilmiştir.
- [XSStrike](https://github.com/s0md3v/XSStrike) - XSStrike, XSS için parametreleri bulanıklaştırabilen ve kaba kuvvet saldırıları gerçekleştirebilen bir programdır. Ayrıca WAF'ları tespit edip atlayabilir - [@s0md3v](https://github.com/s0md3v) tarafından geliştirilmiştir.
- [xssor2](https://github.com/evilcos/xssor2) - XSS'OR - JavaScript ile Hack - [@evilcos](https://github.com/evilcos) tarafından geliştirilmiştir.
- [csp değerlendirici](https://csper.io/evaluator) - İçerik güvenlik politikalarını değerlendirmek için bir araç - [Csper](http://csper.io) tarafından geliştirilmiştir.

<a name="tools-sql-injection"></a>
#### SQL Enjeksiyonu

- [sqlmap](https://github.com/sqlmapproject/sqlmap) - Otomatik SQL enjeksiyon ve veritabanı ele geçirme aracı.

<a name="tools-template-injection"></a>
#### Şablon Enjeksiyonu

- [tplmap](https://github.com/epinna/tplmap) - Kod ve Sunucu Tarafı Şablon Enjeksiyon Tespit ve Sömürme Aracı - [@epinna](https://github.com/epinna) tarafından geliştirilmiştir.

<a name="tools-xxe"></a>
#### XXE (XML Harici Varlık Saldırısı)

- [dtd-finder](https://github.com/GoSecure/dtd-finder) - Yerel DTD'leri listeler ve bu DTD'leri kullanarak XXE yükleri oluşturur - [@GoSecure](https://github.com/GoSecure) tarafından geliştirilmiştir.

<a name="tools-csrf"></a>
#### Siteler Arası İstek Sahteciliği (CSRF)

- [XSRFProbe](https://github.com/0xInfection/XSRFProbe) - Birinci Sınıf CSRF Denetim ve Sömürü Araç Seti - [@0xInfection](https://github.com/0xinfection) tarafından geliştirilmiştir.

<a name="tools-ssrf"></a>
#### Sunucu Tarafı İstek Sahteciliği (SSRF)

- [Açık yönlendirme/SSRF yük üreteci](https://tools.intigriti.io/redirector/) - Açık yönlendirme/SSRF yükleri oluşturma aracı - [intigriti](https://www.intigriti.com/) tarafından sunulmaktadır.

<a name="tools-leaking"></a>
### Bilgi Sızıntısı

- [HTTPLeaks](https://github.com/cure53/HTTPLeaks) - Bir web sitesinin HTTP isteklerini sızdırabileceği tüm olası yollar - [@cure53](https://github.com/cure53) tarafından geliştirilmiştir.
- [dvcs-ripper](https://github.com/kost/dvcs-ripper) - Web üzerinden erişilebilen (dağıtılmış) sürüm kontrol sistemlerini çıkarma aracı: SVN/GIT/HG... - [@kost](https://github.com/kost) tarafından geliştirilmiştir.
- [DVCS-Pillage](https://github.com/evilpacket/DVCS-Pillage) - Web üzerinden erişilebilen GIT, HG ve BZR depolarını yağmalama aracı - [@evilpacket](https://github.com/evilpacket) tarafından geliştirilmiştir.
- [GitMiner](https://github.com/UnkL4b/GitMiner) - Github'da içerik aramak için gelişmiş madencilik aracı - [@UnkL4b](https://github.com/UnkL4b) tarafından geliştirilmiştir.
- [gitleaks](https://github.com/zricethezav/gitleaks) - Gizli bilgiler ve anahtarlar için depo geçmişini tamamen tarar - [@zricethezav](https://github.com/zricethezav) tarafından geliştirilmiştir.
- [CSS-Keylogging](https://github.com/maxchehab/CSS-Keylogging) - CSS'in tuş kaydetme yeteneklerinden yararlanan Chrome eklentisi ve Express sunucusu - [@maxchehab](https://github.com/maxchehab) tarafından geliştirilmiştir.
- [pwngitmanager](https://github.com/allyshka/pwngitmanager) - Pentester'lar için Git yöneticisi - [@allyshka](https://github.com/allyshka) tarafından geliştirilmiştir.
- [snallygaster](https://github.com/hannob/snallygaster) - HTTP sunucularında gizli dosyaları taramak için bir araç - [@hannob](https://github.com/hannob) tarafından geliştirilmiştir.
- [LinkFinder](https://github.com/GerbenJavado/LinkFinder) - JavaScript dosyalarında uç noktaları bulan Python betiği - [@GerbenJavado](https://github.com/GerbenJavado) tarafından geliştirilmiştir.

<a name="tools-detecting"></a>
### Tespit Etme

- [sqlchop](https://sqlchop.chaitin.cn/) - SQL enjeksiyon tespit motoru - [chaitin](http://chaitin.com) tarafından geliştirilmiştir.
- [xsschop](https://xsschop.chaitin.cn/) - XSS tespit motoru - [chaitin](http://chaitin.com) tarafından geliştirilmiştir.
- [retire.js](https://github.com/RetireJS/retire.js) - Bilinen güvenlik açıklarına sahip JavaScript kütüphanelerinin kullanımını tespit eden tarayıcı - [@RetireJS](https://github.com/RetireJS) tarafından geliştirilmiştir.
- [malware-jail](https://github.com/HynekPetrak/malware-jail) - Yarı otomatik JavaScript zararlı yazılım analizi, kod çözme ve yük çıkarma için sanal ortam - [@HynekPetrak](https://github.com/HynekPetrak) tarafından geliştirilmiştir.
- [repo-supervisor](https://github.com/auth0/repo-supervisor) - Kodunuzu güvenlik yanlış yapılandırmaları, şifreler ve gizli bilgiler için tarar.
- [bXSS](https://github.com/LewisArdern/bXSS) - bXSS, [cure53.de/m](https://cure53.de/m)'den uyarlanmış basit bir Blind XSS uygulamasıdır - [@LewisArdern](https://github.com/LewisArdern) tarafından geliştirilmiştir.
- [OpenRASP](https://github.com/baidu/openrasp) - Baidu Inc. tarafından aktif olarak sürdürülen açık kaynaklı bir RASP çözümü. Bağlama duyarlı tespit algoritması sayesinde proje neredeyse hiç yanlış pozitif sonuç üretmez. Ağır sunucu yükü altında bile performans düşüşü %3'ün altında gözlemlenmiştir.
- [GuardRails](https://github.com/apps/guardrails) - Pull Request'lerde güvenlik geri bildirimi sağlayan bir GitHub Uygulaması.

<a name="tools-preventing"></a>
### Önleme

- [DOMPurify](https://github.com/cure53/DOMPurify) - Sadece DOM için, süper hızlı, aşırı toleranslı HTML, MathML ve SVG XSS temizleyicisi - [Cure53](https://cure53.de/) tarafından geliştirilmiştir.
- [js-xss](https://github.com/leizongmin/js-xss) - Beyaz liste ile yapılandırılmış güvenilmeyen HTML'yi temizleme (XSS'i önlemek için) - [@leizongmin](https://github.com/leizongmin) tarafından geliştirilmiştir.
- [Acra](https://github.com/cossacklabs/acra) - SQL veritabanları için istemci tarafı şifreleme motoru, güçlü seçici şifreleme, SQL enjeksiyonlarını önleme ve izinsiz giriş tespiti ile - [@cossacklabs](https://www.cossacklabs.com/) tarafından geliştirilmiştir.
- [Csper](https://csper.io) - Siteler arası betik çalıştırmayı önlemek/tespit etmek için içerik güvenlik politikaları oluşturmak/değerlendirmek/izlemek için bir araç seti - [Csper](https://csper.io) tarafından geliştirilmiştir.

<a name="tools-proxy"></a>
### Vekil Sunucu (Proxy)

- [Charles](https://www.charlesproxy.com/) - Bir geliştiricinin bilgisayarı ile internet arasındaki tüm HTTP ve SSL/HTTPS trafiğini görüntülemesini sağlayan HTTP vekil sunucusu / HTTP monitörü / Ters Vekil Sunucu.
- [mitmproxy](https://github.com/mitmproxy/mitmproxy) - Penetrasyon testçileri ve yazılım geliştiriciler için etkileşimli TLS özellikli araya giren HTTP vekil sunucusu - [@mitmproxy](https://github.com/mitmproxy) tarafından geliştirilmiştir.

<a name="tools-webshell"></a>
### Web Kabuğu (Webshell)

- [nano](https://github.com/s0md3v/nano) - Kod golfü ile oluşturulmuş PHP kabukları ailesi - [@s0md3v](https://github.com/s0md3v) tarafından geliştirilmiştir.
- [webshell](https://github.com/tennc/webshell) - Açık kaynaklı bir web kabuğu projesi - [@tennc](https://github.com/tennc) tarafından geliştirilmiştir.
- [Weevely](https://github.com/epinna/weevely3) - Silahlandırılmış web kabuğu - [@epinna](https://github.com/epinna) tarafından geliştirilmiştir.
- [Webshell-Sniper](https://github.com/WangYihang/Webshell-Sniper) - Web sitenizi terminal üzerinden yönetin - [@WangYihang](https://github.com/WangYihang) tarafından geliştirilmiştir.
- [Reverse-Shell-Manager](https://github.com/WangYihang/Reverse-Shell-Manager) - Terminal üzerinden Ters Kabuk Yöneticisi - [@WangYihang](https://github.com/WangYihang) tarafından geliştirilmiştir.
- [reverse-shell](https://github.com/lukechilds/reverse-shell) - Hizmet olarak Ters Kabuk - [@lukechilds](https://github.com/lukechilds) tarafından geliştirilmiştir.
- [PhpSploit](https://github.com/nil0x42/phpsploit) - Kötü amaçlı PHP tek satırı ile web sunucusunda sessizce kalıcı olan tam özellikli C2 çerçevesi - [@nil0x42](https://github.com/nil0x42) tarafından geliştirilmiştir.

<a name="tools-disassembler"></a>
### Ayrıştırıcı (Disassembler)

- [plasma](https://github.com/plasma-disassembler/plasma) - x86/ARM/MIPS için etkileşimli bir ayrıştırıcı - [@plasma-disassembler](https://github.com/plasma-disassembler) tarafından geliştirilmiştir.
- [radare2](https://github.com/radare/radare2) - Unix benzeri tersine mühendislik çerçevesi ve komut satırı araçları - [@radare](https://github.com/radare) tarafından geliştirilmiştir.
- [Iaitō](https://github.com/hteso/iaito) - radare2 tersine mühendislik çerçevesi için Qt ve C++ arayüzü - [@hteso](https://github.com/hteso) tarafından geliştirilmiştir.

<a name="tools-decompiler"></a>
### Ayrıştırıcı (Decompiler)

- [CFR](http://www.benf.org/other/cfr/) - Başka bir Java ayrıştırıcı - [@LeeAtBenf](https://twitter.com/LeeAtBenf) tarafından geliştirilmiştir.

<a name="tools-dns-rebinding"></a>
### DNS Yeniden Bağlama (DNS Rebinding)

- [DNS Rebind Toolkit](https://github.com/brannondorsey/dns-rebind-toolkit) - Yerel ağdaki (LAN) savunmasız ana bilgisayarlara ve hizmetlere karşı DNS Yeniden Bağlama sömürüleri geliştirmek için bir ön uç JavaScript çerçevesi - [@brannondorsey](https://github.com/brannondorsey) tarafından geliştirilmiştir
- [dref](https://github.com/mwrlabs/dref) - DNS Yeniden Bağlama Sömürü Çerçevesi. Dref, DNS yeniden bağlama işlemlerini kolaylaştırır - [@mwrlabs](https://github.com/mwrlabs) tarafından geliştirilmiştir
- [Singularity of Origin](https://github.com/nccgroup/singularity) - Saldırı sunucusunun DNS adresinin IP'sini hedef makinenin IP adresine yeniden bağlamak ve hedef makinedeki savunmasız yazılımları sömürmek için saldırı yüklerini sunmak için gerekli bileşenleri içerir - [@nccgroup](https://github.com/nccgroup) tarafından geliştirilmiştir
- [Whonow DNS Server](https://github.com/brannondorsey/whonow) - Anında DNS Yeniden Bağlama saldırıları gerçekleştirmek için kötü amaçlı bir DNS sunucusu - [@brannondorsey](https://github.com/brannondorsey) tarafından geliştirilmiştir

<a name="tools-others"></a>
### Diğerleri

- [Dnslogger](https://wiki.skullsecurity.org/index.php?title=Dnslogger) - DNS Günlükleyici - [@iagox86](https://github.com/iagox86) tarafından geliştirilmiştir.
- [CyberChef](https://github.com/gchq/CyberChef) - Siber İsviçre Çakısı - şifreleme, kodlama, sıkıştırma ve veri analizi için bir web uygulaması - [@GCHQ](https://github.com/gchq) tarafından geliştirilmiştir.
- [ntlm_challenger](https://github.com/b17zr/ntlm_challenger) - HTTP üzerinden NTLM meydan okuma mesajlarını ayrıştırır - [@b17zr](https://github.com/b17zr) tarafından geliştirilmiştir.
- [cefdebug](https://github.com/taviso/cefdebug) - CEF hata ayıklayıcısına bağlanmak için minimum kod - [@taviso](https://github.com/taviso) tarafından geliştirilmiştir.
- [ctftool](https://github.com/taviso/ctftool) - Etkileşimli CTF Keşif Aracı - [@taviso](https://github.com/taviso) tarafından geliştirilmiştir.

## Sosyal Mühendislik Veritabanı

- [haveibeenpwned](https://haveibeenpwned.com/) - Bir veri ihlalinde ele geçirilmiş bir hesabınız olup olmadığını kontrol edin - [Troy Hunt](https://www.troyhunt.com/) tarafından oluşturulmuştur.

## Bloglar

- [Orange](http://blog.orange.tw/) - Tayvan'ın yetenekli web penetrasyon uzmanı.
- [leavesongs](https://www.leavesongs.com/) - Çin'in yetenekli web penetrasyon uzmanı.
- [James Kettle](http://albinowax.skeletonscribe.net/) - [PortSwigger Web Security](https://portswigger.net/)'de Araştırma Başkanı.
- [Broken Browser](https://www.brokenbrowser.com/) - Tarayıcı Açıklıklarıyla Eğlence.
- [Scrutiny](https://datarift.blogspot.tw/) - Dhiraj Mishra tarafından Web Tarayıcıları Üzerinden İnternet Güvenliği.
- [BRETT BUERHAUS](https://buer.haus/) - Güvenlik Açığı Açıklamaları ve Uygulama Güvenliği Üzerine Yazılar.
- [n0tr00t](https://www.n0tr00t.com/) - ~# n0tr00t Güvenlik Ekibi.
- [OpnSec](https://opnsec.com/) - Açık Fikirli Güvenlik!
- [RIPS Technologies](https://blog.ripstech.com/tags/security/) - PHP güvenlik açıkları için yazılar.
- [0Day Labs](http://blog.0daylabs.com/) - Harika ödül avcılığı ve zorluk yazıları.
- [Blog of Osanda](https://osandamalith.com/) - Güvenlik Araştırmaları ve Tersine Mühendislik.

## Twitter Kullanıcıları

- [@HackwithGitHub](https://twitter.com/HackwithGithub) - Hacker'lar ve penetrasyon testçileri için açık kaynaklı hack araçlarını sergileme girişimi
- [@filedescriptor](https://twitter.com/filedescriptor) - Aktif penetrasyon testçisi, sıklıkla tweet atar ve faydalı makaleler yazar
- [@cure53berlin](https://twitter.com/cure53berlin) - [Cure53](https://cure53.de/) bir Alman siber güvenlik firmasıdır.
- [@XssPayloads](https://twitter.com/XssPayloads) - JavaScript'in beklenmedik kullanımlarının harikalar diyarı ve daha fazlası.
- [@kinugawamasato](https://twitter.com/kinugawamasato) - Japon web penetrasyon uzmanı.
- [@h3xstream](https://twitter.com/h3xstream/) - Güvenlik Araştırmacısı, web güvenliği, kripto, penetrasyon testi, statik analizle ilgileniyor ama en önemlisi, samy benim kahramanım.
- [@garethheyes](https://twitter.com/garethheyes) - İngiliz web penetrasyon uzmanı.
- [@hasegawayosuke](https://twitter.com/hasegawayosuke) - Japon JavaScript güvenlik araştırmacısı.
- [@shhnjk](https://twitter.com/shhnjk) - Web ve Tarayıcı Güvenliği Araştırmacısı.

## Uygulamalar

<a name="practices-application"></a>
### Uygulama

- [OWASP Juice Shop](https://github.com/bkimminich/juice-shop) - Muhtemelen en modern ve sofistike güvensiz web uygulaması - [@bkimminich](https://github.com/bkimminich) ve [@owasp_juiceshop](https://twitter.com/owasp_juiceshop) ekibi tarafından yazılmıştır.
- [BadLibrary](https://github.com/SecureSkyTechnology/BadLibrary) - Eğitim için savunmasız web uygulaması - [@SecureSkyTechnology](https://github.com/SecureSkyTechnology) tarafından yazılmıştır.
- [Hackxor](http://hackxor.net/) - Gerçekçi web uygulaması hack oyunu - [@albinowax](https://twitter.com/albinowax) tarafından yazılmıştır.
- [SELinux Game](http://selinuxgame.org/) - Yaparak SELinux öğrenin. Bulmacaları çözün, yeteneklerinizi gösterin - [@selinuxgame](https://twitter.com/selinuxgame) tarafından yazılmıştır.
- [Portswigger Web Security Academy](https://portswigger.net/web-security) - Ücretsiz eğitimler ve laboratuvarlar - [PortSwigger](https://portswigger.net/) tarafından sağlanmaktadır.

<a name="practices-aws"></a>
### AWS

- [FLAWS](http://flaws.cloud/) - Amazon AWS CTF yarışması - [@0xdabbad00](https://twitter.com/0xdabbad00) tarafından oluşturulmuştur.
- [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat) - Rhino Security Labs'ın "Tasarımdan Dolayı Savunmasız" AWS altyapı kurulum aracı - [@RhinoSecurityLabs](https://github.com/RhinoSecurityLabs) tarafından geliştirilmiştir.

<a name="practices-xss"></a>
### XSS

- [XSS game](https://xss-game.appspot.com/) - Google XSS Mücadelesi - Google tarafından oluşturulmuştur.
- [prompt(1) to win](http://prompt.ml/) - 2014 yazında düzenlenen 16 Seviyeli (+4 Gizli Seviye) Karmaşık XSS Mücadelesi - [@cure53](https://github.com/cure53) tarafından oluşturulmuştur.
- [alert(1) to win](https://alf.nu/alert1) - XSS mücadele serisi - [@steike](https://twitter.com/steike) tarafından oluşturulmuştur.
- [XSS Challenges](http://xss-quiz.int21h.jp/) - XSS mücadele serisi - yamagata21 tarafından oluşturulmuştur.

<a name="practices-modsecurity"></a>
### ModSecurity / OWASP ModSecurity Çekirdek Kural Seti

- [ModSecurity / OWASP ModSecurity Çekirdek Kural Seti](https://www.netnea.com/cms/apache-tutorials/) - ModSecurity ve Çekirdek Kural Seti'ni kurmak, yapılandırmak ve ayarlamak için eğitim serisi - [@ChrFolini](https://twitter.com/ChrFolini) tarafından yazılmıştır.

## Topluluk

- [Reddit](https://www.reddit.com/r/websecurity/)
- [Stack Overflow](http://stackoverflow.com/questions/tagged/security)

## Çeşitli

- [awesome-bug-bounty](https://github.com/djadmin/awesome-bug-bounty) - Mevcut Hata Avı ve Açıklama Programları ve yazılarının kapsamlı derlenmiş listesi - [@djadmin](https://github.com/djadmin) tarafından derlenmiştir.
- [bug-bounty-reference](https://github.com/ngalongc/bug-bounty-reference) - Hata türüne göre kategorize edilmiş hata avı yazıları listesi - [@ngalongc](https://github.com/ngalongc) tarafından derlenmiştir.
- [Google VRP and Unicorns](https://sites.google.com/site/bughunteruniversity/behind-the-scenes/presentations/google-vrp-and-unicorns) - [Daniel Stelter-Gliese](https://www.linkedin.com/in/daniel-stelter-gliese-170a70a2/) tarafından yazılmıştır.
- [Facebook E-posta ve Telefon Numaranızı Kaba Kuvvet Saldırısı ile Bulma](http://pwndizzle.blogspot.jp/2014/02/brute-forcing-your-facebook-email-and.html) - [PwnDizzle](http://pwndizzle.blogspot.jp/) tarafından yazılmıştır.
- [Pentest + Exploit Geliştirme Kılavuz Duvar Kağıdı](http://i.imgur.com/Mr9pvq9.jpg) - Sızma Testleri ve Exploit Geliştirme Kılavuzu.
- [Kesin Güvenlik Veri Bilimi ve Makine Öğrenimi Kılavuzu](http://www.covert.io/the-definitive-security-datascience-and-machinelearning-guide/) - JASON TROS tarafından yazılmıştır.
- [EQGRP](https://github.com/x0rz/EQGRP) - eqgrp-auction-file.tar.xz dosyasının şifresi çözülmüş içeriği - [@x0rz](https://github.com/x0rz) tarafından paylaşılmıştır.
- [notlar](https://github.com/ChALkeR/notes) - [@ChALkeR](https://github.com/ChALkeR) tarafından paylaşılan bazı genel notlar.
- [GitHub'ın Hata Avı İş Akışına Kısa Bir Bakış](https://githubengineering.com/githubs-bug-bounty-workflow/) - [@gregose](https://github.com/gregose) tarafından yazılmıştır.
- [Siber Güvenlik Kampanya Kılavuzu](https://www.belfercenter.org/CyberPlaybook) - [Belfer Center for Science and International Affairs](https://www.belfercenter.org/) tarafından hazırlanmıştır.
- [Infosec_Reference](https://github.com/rmusser01/Infosec_Reference) - Sıkmayan Bilgi Güvenliği Referansı - [@rmusser01](https://github.com/rmusser01) tarafından derlenmiştir.
- [Nesnelerin İnterneti Tarayıcısı](http://iotscanner.bullguard.com/) - Evinizdeki internete bağlı cihazlarınızın Shodan'da herkese açık olup olmadığını kontrol edin - [BullGuard](https://www.bullguard.com/) tarafından sağlanmıştır.
- [Hata Avcıları Metodolojisi v2.1](https://docs.google.com/presentation/d/1VpRT8dFyTaFpQa9jhehtmGaC7TqQniMSYbUdlHN6VrY/edit?usp=sharing) - [@jhaddix](https://twitter.com/jhaddix) tarafından yazılmıştır.
- [7.500$'lık Google servisleri karışıklığı](https://sites.google.com/site/testsitehacking/-7-5k-Google-services-mix-up) - [Ezequiel Pereira](https://sites.google.com/site/testsitehacking/) tarafından yazılmıştır.
- [Paylaşımlı barındırma kullanarak herhangi bir etki alanı için Let's Encrypt SSL sertifikası veren ACME TLS-SNI-01'i nasıl sömürdüm](https://labs.detectify.com/2018/01/12/how-i-exploited-acme-tls-sni-01-issuing-lets-encrypt-ssl-certs-for-any-domain-using-shared-hosting/) - [@fransrosen](https://twitter.com/fransrosen) tarafından yazılmıştır.
- [ÖZET: WebRTC üzerinden VPN kullanıcılarının IP'leri sızıyor. Yetmiş VPN sağlayıcısını test ettim ve 16'sı (%23) WebRTC üzerinden kullanıcı IP'lerini sızdırıyor](https://voidsec.com/vpn-leak/) - [voidsec](https://voidsec.com/) tarafından yazılmıştır.
- [Kısıtlı Ağlardan Kaçış ve Gizlenme](https://www.optiv.com/blog/escape-and-evasion-egressing-restricted-networks) - [Chris Patten, Tom Steele](info@optiv.com) tarafından yazılmıştır.
- [Kopyaladığınız şeye dikkat edin: Sıfır Genişlikli Karakterlerle metinlere görünmez kullanıcı adları ekleme](https://medium.com/@umpox/be-careful-what-you-copy-invisibly-inserting-usernames-into-text-with-zero-width-characters-18b4e6f17b66) - [@umpox](https://medium.com/@umpox) tarafından yazılmıştır.
- [Domato Fuzzer'ın Üretim Motoru İç Yapısı](https://www.sigpwn.io/blog/2018/4/14/domato-fuzzers-generation-engine-internals) - [sigpwn](https://www.sigpwn.io/) tarafından yazılmıştır.
- [CSS O Kadar Güçlü ki Facebook Kullanıcılarının Anonimliğini Kaldırabilir](https://www.evonide.com/side-channel-attacking-browsers-through-css3-features/) - [Ruslan Habalov](https://www.evonide.com/) tarafından yazılmıştır.
- [Web Uygulama Güvenliğine Giriş](https://www.slideshare.net/nragupathy/introduction-to-web-application-security-blackhoodie-us-2018) - [@itsC0rg1](https://twitter.com/itsC0rg1), [@jmkeads](https://twitter.com/jmkeads) ve [@matir](https://twitter.com/matir) tarafından yazılmıştır.
- [CloudFlare veya TOR Arkasında Gizlenen Gerçek Köken IP'lerini Bulma](https://www.secjuice.com/finding-real-ips-of-origin-servers-behind-cloudflare-or-tor/) - [Paul Dannewitz](https://www.secjuice.com/author/paul-dannewitz/) tarafından yazılmıştır.
- [Neden Facebook'un API'si bir for döngüsüyle başlıyor?](https://dev.to/antogarand/why-facebooks-api-starts-with-a-for-loop-1eob) - [@AntoGarand](https://twitter.com/AntoGarand) tarafından yazılmıştır.
- [Google'dan Fotoğraflarınızı Nasıl Çalabilirdim - İlk 3 Hata Avı Yazım](https://blog.avatao.com/How-I-could-steal-your-photos-from-Google/) - [@gergoturcsanyi](https://twitter.com/gergoturcsanyi) tarafından yazılmıştır.
- [NAT'ın neden güvenlik olmadığına dair bir örnek](https://0day.work/an-example-why-nat-is-not-security/) - [@0daywork](https://twitter.com/@0daywork) tarafından yazılmıştır.
- [WEB UYGULAMA SIZMA TESTİ NOTLARI](https://techvomit.net/web-application-penetration-testing-notes/) - [Jayson](https://techvomit.net/) tarafından yazılmıştır.
- [Baş Üstü Ekran ile Hackleme](https://segment.com/blog/hacking-with-a-heads-up-display/) - [David Scrobonia](https://segment.com/blog/authors/david-scrobonia/) tarafından yazılmıştır.
- [Alexa İlk 1 Milyon Güvenlik - Büyükleri Hacklemek](https://slashcrypto.org/data/itsecx2018.pdf) - [@slashcrypto](https://twitter.com/slashcrypto) tarafından yazılmıştır.
- [Hayatımı değiştiren hata avı programı](http://10degres.net/the-bug-bounty-program-that-changed-my-life/) - [Gwen](http://10degres.net/) tarafından yazılmıştır.
- [Hata avı yazıları listesi](https://pentester.land/list-of-bug-bounty-writeups.html) - [Mariem](https://pentester.land/) tarafından derlenmiştir.
- [.NET Derlemelerini Yüklemenin Etkileri](https://threatvector.cylance.com/en_us/home/implications-of-loading-net-assemblies.html) - [Brian Wallace](https://threatvector.cylance.com/en_us/contributors/brian-wallace.html) tarafından yazılmıştır.
- [WCTF2019: Gyotaku The Flag](https://westerns.tokyo/wctf2019-gtf/wctf2019-gtf-slides.pdf) - [@t0nk42](https://twitter.com/t0nk42) tarafından yazılmıştır.
- [Slack'in TURN sunucularını iç hizmetlere erişmek için nasıl kötüye kullandık](https://www.rtcsec.com/2020/04/01-slack-webrtc-turn-compromise/) - [@sandrogauci](https://twitter.com/sandrogauci) tarafından yazılmıştır.
- [DOS Dosya Yolu Sihirli Numeraları](https://medium.com/walmartlabs/dos-file-path-magic-tricks-5eda7a7a85fa) - [@clr2of8](https://medium.com/@clr2of8) tarafından yazılmıştır.
- [Tesla'dan ilk büyük hata avı ödememi nasıl aldım](https://medium.com/heck-the-packet/how-i-got-my-first-big-bounty-payout-with-tesla-8d28b520162d) - [@cj.fairhead](https://medium.com/@cj.fairhead) tarafından yazılmıştır.

## Davranış Kuralları

Lütfen bu projenin bir [Katılımcı Davranış Kuralları](code-of-conduct.md) ile yayınlandığını unutmayın. Bu projeye katılarak şartlarını kabul etmiş sayılırsınız.

## Lisans

[![CC0](http://mirrors.creativecommons.org/presskit/buttons/88x31/svg/cc-zero.svg)](https://creativecommons.org/publicdomain/zero/1.0/)

Bu çalışma [Creative Commons CC0 1.0 Evrensel](https://creativecommons.org/publicdomain/zero/1.0/) lisansı altında yayınlanmıştır.

Yürürlükteki yasalar çerçevesinde mümkün olan en üst düzeyde, [@qazbnm456](https://qazbnm456.github.io/) bu çalışma üzerindeki tüm telif hakkı ve ilgili veya komşu haklarından feragat etmiştir.
