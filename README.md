**DevSecOps CI/CD Pipeline Using Jenkins**

**By Ahmed Pinger**

# **Introduction**

Securing web applications is today's most common aspect of securing the
enterprise. Web application hacking is on the rise with as many as 80%
of cyber-attacks done at the web application level. The OWASP foundation
provides the top 10 vulnerabilities which are the most common and the
most critical from top to bottom.

So, in this project, we will be looking over some of the vulnerabilities
and deploying an automated Web Application with all security checks.

Some major software and frameworks used in the project are listed below.

-   Ansible

-   Jenkins

-   OWASP Dependency Check

# **Project Implementation Plan**

We will be having a total of 6 steps in the deployment of the whole
project which are listed below.

-   Design

-   Designing Playbooks

-   Setting up Software

-   Integrating software with other software

-   Making all jobs in Jenkins

-   Designing the pipeline

# **Version Control**

| Title         | DevSecOps CI/CD Pipeline                                     |
|---------------|--------------------------------------------------------------|
| Description   | Secure Deployment of a Web application using CI/CD Pipelines |
| Created By    | Ahmed Pinger                                                 |
| Maintained By | Ahmed Pinger                                                 |
| Date Created  | 17th December 2022                                           |

# **Table Of Contents**

**[Introduction](#introduction)**

**[Project Implementation Plan](#project-implementation-plan)**

**[Version Control](#version-control)**

**[Table Of Contents](#table-of-contents)**

**[Scope Of Work](#scope-of-work)** 

**[Project Flow](#project-flow)** 

> [Design](#design)
> 
> [Designing Playbooks](#designing-playbooks)
> 
> [IaC Checks](#iac-checks)
> 
> [Explanation](#explanation)
> 
> [Results](#results)
> 
> [Cloning](#cloning)
>
> [Explanation](#explanation-1)
> 
> [Results](#results-1)
> 
> [HTTPd Installation](#httpd-installation)
> 
> [Explanation](#explanation-2)
> 
> [Results](#results-2) 
>
> [Use HTTPS Only](#use-https-only)
> 
> [Explanation](#explanation-3)
> 
> [Results](#results-3)
> 
> [Port Redirection](#port-redirection)
> 
> [Explanation](#explanation-4)
> 
> [Results](#results-4)
> 
> [Least Privilege](#least-privilege)
> 
> [Explanation](#explanation-5)
> 
> [Results](#results-5)
> 
> [Activating TLS Listener](#activating-tls-listener)
> 
> [Explanation](#explanation-6)
> 
> [Results](#results-6)
> 
> [HTTPS Header Security](#https-header-security)
> 
> [Explanation](#explanation-7)
> 
> [Results](#results-7)
> 
> [Setting up Softwares](#setting-up-softwares)
> 
> [Installing Ansible](#installing-ansible)
> 
> [Linux:](#linux)
> 
> [MacOS:](#macos)
> 
> [Windows:](#windows)
> 
> [Installing Jenkins](#installing-jenkins)
> 
> [Linux:](#linux-1) 
> 
> [MacOS:](#macos-1) 
> 
> [Windows:](#windows-1)
> 
> [Installing OWASP Dependency
> 
> Check](#installing-owasp-dependency-check)
> 
> [Linux:](#linux-2)
> 
> [MacOS:](#macos-2)
> 
> [Windows:](#windows-2)
> 
> [Integrating software with other
> 
> software](#integrating-software-with-other-software)
> 
> [Installing Ansible plugin
> 
> Jenkins](#installing-ansible-plugin-jenkins)
> 
> [Installing OWASP Dependency-Check Plugin On
> 
> Jenkins](#installing-owasp-dependency-check-plugin-on-jenkins)
> 
> [Installing Git plugin in Jenkins](#installing-git-plugin-in-jenkins)
> 
> [Linux:](#linux-3)
> 
> [MacOS:](#macos-3)
> 
> [Windows:](#windows-3)
> 
> [Making all jobs in Jenkins](#making-all-jobs-in-jenkins)
> 
> [Results](#results-8)
> 
> [Results](#results-9)
> 
> [Designing the pipeline](#designing-the-pipeline)
> 
> [Testing & Results](#testing-results) 

# **Scope Of Work**

| Sr. No. | Tasks                         | Comments |
|---------|-------------------------------|----------|
| 1       | Network Design                |          |          
| 2       | Designing Playbooks           |          |          
| 3       | Software Setup                |          |          
| 4       | Integrate With Other Software |          |          
| 5       | Making Jobs In Jenkins        |          |          
| 6       | Making Pipeline               |          |         

# **Project Flow**

## **Design**

Downloading an ISO of RHEL and installing the operating system in VMware
17 Pro. I use only CLI-based Red Hat because it is easy to manage from
its Web Interface and it's light as well.

<img src="media/image3.png" style="width:6.5in;height:3.59722in" />

## 

## **Designing Playbooks**

We have a total of 9 steps in the pipeline, but the one in which the
dependency check will be done from Jenkins only! it does not require the
playbook to be written for it. So we will be writing 8 playbooks of
Ansible to complete our pipeline.

### **IaC Checks**

Starting with the code

```yaml
---
- hosts: all
  vars:
    allowed_ssh_networks:
      - 192.168.0.108/24
    unnecessary_services:
      - postfix
      - telnet.socket
    unnecessary_software:
      - tcpdump
      - nmap-ncat
      - wpa_supplicant
  tasks:
    - name: Allow incoming traffic on port 22
      firewalld:
        permanent: true
        zone: public
        port: 22/tcp
        state: enabled

    - name: Add rule to allow SSH from 192.168.0.108
      ansible.builtin.iptables:
        chain: INPUT
        protocol: tcp
        destination_port: 22
        source: 192.168.0.108
        jump: ACCEPT
        state: present

    - name: Add rule to allow Red Hat Web Controller from 192.168.0.108
      ansible.builtin.iptables:
        chain: INPUT
        protocol: tcp
        destination_port: 9090
        source: 192.168.0.108
        jump: ACCEPT
        state: present

    - name: Add default deny rule for SSH
      ansible.builtin.iptables:
        chain: INPUT
        protocol: tcp
        destination_port: 22
        source: 0.0.0.0/0
        jump: REJECT
        state: present

    - name: Add default deny rule for Red Hat Web Controller
      ansible.builtin.iptables:
        chain: INPUT
        protocol: tcp
        destination_port: 9090
        source: 0.0.0.0/0
        jump: REJECT
        state: present

    - name: Reload firewalld
      shell: firewall-cmd --reload
      register: firewalld_reload

    - name: Debug output
      debug:
        var: firewalld_reload

    - name: Perform full patching
      package:
        name: '*'
        state: latest

    - name: Add hardened SSH config
      copy:
        dest: /etc/ssh/sshd_config
        src: /etc/ssh/sshd_config
        owner: root
        group: root
        mode: 0600
        notify: Reload SSH

    - name: Remove undesirable packages
      package:
        name: "{{ unnecessary_software }}"
        state: absent

    - name: Stop and disable unnecessary services
      service:
        name: "{{ item }}"
        state: stopped
        enabled: no
      with_items: "{{ unnecessary_services }}"
      ignore_errors: yes

  handlers:
    - name: Reload SSH
      service:
        name: sshd
        state: reloaded
```
#### **Explanation**

This Ansible playbook is used to configure the firewall and SSH settings
on a group of servers (indicated by the hosts: all line). It also
performs some system maintenance tasks such as patching and removing
unnecessary software and services.

Here is a breakdown of the tasks in the playbook:

-   The first task allows incoming traffic on port 22 and adds a rule to
    > allow SSH connections from the IP address 192.168.0.108. This is
    > done using the firewalld and ansible.builtin.iptables modules.

-   The second task adds a rule to allow incoming traffic on port 9090
    > from the IP address 192.168.0.108. This is used for the Red Hat
    > Web Controller.

-   The third task adds default deny rules for both SSH and the Red Hat
    > Web Controller. This means that any incoming traffic on these
    > ports from any IP address will be rejected.

-   The fourth task reloads the firewalld service using the shell
    > module.

-   The fifth task is a debug task that outputs the result of the
    > firewalld reload command.

-   The sixth task performs a full system patching by upgrading all
    > installed packages to the latest version.

-   The seventh task adds a hardened SSH configuration file to the
    > server.

-   The eighth task removes unnecessary software packages.

-   The ninth task stops and disables unnecessary services.

Finally, the playbook includes a handler called "Reload SSH" which is
used to reload the SSH service after the SSH configuration file is
modified.

#### **Results**

<img src="media/image2.png" style="width:6.5in;height:7.72222in" />

### **Cloning**

Starting with the code
```yaml
---

\- hosts: all

tasks:

\- name: install git

yum:

name: git

state: present

\- name: clone git repository

git:

repo: https://github.com/AhmedPinger/DevSecOps-CI-CD-Pipeline-Using-Jenkins/Vulnerable-WebApp.git

dest: /var/www/html

force: true
```
#### **Explanation**

This Ansible playbook is used to install the git package and clone a git
repository onto a group of servers (indicated by the hosts: all line).

Here is a breakdown of the tasks in the playbook:

-   The first task installs the git package using the yum module.

-   The second task clones the git repository located at
    > https://github.com/AhmedPinger/Vulnerable-WebApp.git to the
    > /var/www/html directory on the servers. The force option is set to
    > true which means that the clone will overwrite any existing files
    > in the destination directory.

Overall, this playbook installs the git package and clones a specific
git repository onto a group of servers.

#### **Results**

<img src="media/image8.png" style="width:6.5in;height:2.20833in" />

### **HTTPd Installation**

Starting with the code
```yaml
---

# This playbook installs the Apache HTTP server

\- name: Install Apache HTTP server

hosts: linux

become: yes

tasks:

\- name: Install the Apache HTTP server

yum:

name: httpd

state: present

\- name: Ensure the Apache HTTP server is running

service:

name: httpd

state: started
```
#### **Explanation**

This ansible-playbook is used to install the Apache HTTP server on a
group of Linux servers.

Here is a breakdown of the tasks in the playbook:

-   The first task installs the httpd package using the yum module. This
    > package includes the Apache HTTP server.

-   The second task starts with the Apache HTTP server using the service
    > module.

Overall, this playbook installs the Apache HTTP server and ensures that
it is running on a group of Linux servers.

#### **Results**

<img src="media/image1.png" style="width:6.5in;height:2.23611in" />

### **Use HTTPS Only**

Starting with the code
```yaml
---

\- hosts: all

become: yes

tasks:

\- name: Install the Apache HTTP server

yum:

name: httpd

state: present

\- name: Edit the Apache configuration file to disable HTTPS

lineinfile:

path: /etc/httpd/conf/httpd.conf

regexp: '^Listen 443'

line: '# Listen 443'

state: present

\- name: Restart the Apache HTTP server

service:

name: httpd

state: restarted
```
#### **Explanation**

This ansible-playbook is used to install the Apache HTTP server and
disable HTTPS on a group of servers.

Here is a breakdown of the tasks in the playbook:

-   The first task installs the httpd package using the yum module. This
    > package includes the Apache HTTP server.

-   The second task edits the Apache configuration file (located at
    > /etc/httpd/conf/httpd.conf) to disable HTTPS by commenting out the
    > Listen 443 line. This is done using the lineinfile module.

-   The third task restarts the Apache HTTP server using the service
    > module.

Overall, this playbook installs the Apache HTTP server and disables
HTTPS on a group of servers.

#### **Results**

<img src="media/image4.png" style="width:6.5in;height:2.54167in" />

### **Port Redirection**

Starting with the code
```yaml
---

\- hosts: all

tasks:

\- name: Install Apache HTTP Server

package:

name: httpd

state: present

\- name: Update Apache HTTP Server configuration

lineinfile:

path: /etc/httpd/conf/httpd.conf

regexp: '^Listen 80$'

line: 'Listen 8080'

\- name: Restart Apache HTTP Server

service:

name: httpd

state: restarted
```
#### **Explanation**

This ansible-playbook is used to install the Apache HTTP server and
change the port it listens on to 8080 on a group of servers.

Here is a breakdown of the tasks in the playbook:

-   The first task installs the httpd package using the package module.
    > This package includes the Apache HTTP server.

-   The second task updates the Apache configuration file (located at
    > /etc/httpd/conf/httpd.conf) to change the port that the server
    > listens on from 80 to 8080. This is done using the lineinfile
    > module.

-   The third task restarts the Apache HTTP server using the service
    > module to apply the configuration changes.

Overall, this playbook installs the Apache HTTP server and changes the
port it listens on to 8080 on a group of servers.

#### **Results**

<img src="media/image6.png" style="width:6.5in;height:2.66667in" />

### **Least Privilege**

Starting with the code
```
---

\- hosts: all

become: yes

tasks:

\- name: Create the http group

group:

name: http

state: present

\- name: Create the http user

user:

name: http

group: http

system: yes

state: present

\- name: Set the correct permissions on the web root directory

file:

path: /var/www/html

owner: http

group: http

mode: 'u=rwx,g=rx,o=rx'

\- name: Restart the HTTP service

service:

name: httpd

state: restarted
```
#### **Explanation**

This ansible-playbook is used to set up the Apache HTTP server to run as
a non-root user on a group of servers.

Here is a breakdown of the tasks in the playbook:

-   The first task creates the http group using the group module.

-   The second task creates the http user and assigns it to the http
    > group using the user module. The system option is set to yes to
    > indicate that this is a system user.

-   The third task sets the correct permissions on the web root
    > directory (/var/www/html) using the file module. The owner is set
    > to the http user and the group is set to the http group. The mode
    > option sets the permissions to allow the owner and group to read,
    > write, and execute the files, and allows other users to only read
    > and execute the files.

-   The fourth task restarts the Apache HTTP server using the service
    > module to apply the configuration changes.

Overall, this playbook sets up the Apache HTTP server to run as a
non-root user on a group of servers. This is a security best practice as
it reduces the risk of vulnerabilities in the web server being exploited
to gain access to the system.

#### **Results**

<img src="media/image11.png" style="width:6.5in;height:3in" />

### **Activating TLS Listener**

Starting with the code
```yaml
---

\- hosts: all

tasks:

\- name: install Apache

yum:

name: httpd

state: present

\- name: start Apache

service:

name: httpd

state: started

enabled: true

\- name: enable Apache TLS listener

lineinfile:

dest: /etc/httpd/conf.d/ssl.conf

regexp: '^Listen '

line: 'Listen 443'

notify:

\- restart apache

handlers:

\- name: restart apache

service:

name: httpd

state: restarted
```
#### **Explanation**

This ansible-playbook is used to install the Apache HTTP server and
enable HTTPS on a group of servers.

Here is a breakdown of the tasks in the playbook:

-   The first task installs the httpd package using the yum module. This
    > package includes the Apache HTTP server.

-   The second task starts the Apache HTTP server and sets it to start
    > automatically at boot time using the service module.

-   The third task enables the HTTPS listener in the Apache
    > configuration by adding a Listen 443 line to the
    > /etc/httpd/conf.d/ssl.conf file using the lineinfile module. This
    > causes the Apache HTTP server to listen for HTTPS traffic on port
    > 443.

-   The playbook includes a handler called "restart apache" which is
    > used to restart the Apache HTTP server after the configuration is
    > modified.

Overall, this playbook installs the Apache HTTP server and enables HTTPS
on a group of servers.

#### **Results**

<img src="media/image10.png" style="width:6.5in;height:2.91667in" />

### **HTTPS Header Security**

Starting with the code
```yaml
---

\- name: Configure HTTP header security

hosts: linux

become: yes

tasks:

\- name: Install the Apache HTTP server

yum:

name: httpd

state: present

\- name: Ensure the Apache HTTP server is running

service:

name: httpd

state: started

\- name: Set the ServerTokens directive to "Prod"

lineinfile:

path: /etc/httpd/conf/httpd.conf

regexp: '^(ServerTokens) .\*'

line: 'ServerTokens Prod'

state: present

\- name: Set the ServerSignature directive to "Off"

lineinfile:

path: /etc/httpd/conf/httpd.conf

regexp: '^(ServerSignature) .\*'

line: 'ServerSignature Off'

state: present

\- name: Set the X-Frame-Options header to "SAMEORIGIN"

lineinfile:

path: /etc/httpd/conf/httpd.conf

regexp: '^(Header always) .\*'

line: 'Header always set X-Frame-Options "SAMEORIGIN"'

state: present

\- name: Set the X-XSS-Protection header to "1; mode=block"

lineinfile:

path: /etc/httpd/conf/httpd.conf

regexp: '^(Header always) .\*'

line: 'Header always set X-XSS-Protection "1; mode=block"'

state: present

\- name: Set the X-Content-Type-Options header to "nosniff"

lineinfile:

path: /etc/httpd/conf/httpd.conf

regexp: '^(Header always) .\*'

line: 'Header always set X-Content-Type-Options "nosniff"'

state: present

\- name: Set the Strict-Transport-Security header

lineinfile:

path: /etc/httpd/conf/httpd.conf

regexp: '^(Header always) .\*'

line: 'Header always set Strict-Transport-Security "max-age=31536000;
includeSubDomains"'

state: present

\- name: Restart the Apache HTTP server

service:

name: httpd

state: restarted
```
#### **Explanation**

This ansible-playbook is used to configure security headers for the
Apache HTTP server on a group of Linux servers.

Here is a breakdown of the tasks in the playbook:

-   The first task installs the httpd package using the yum module. This
    > package includes the Apache HTTP server.

-   The second task starts with the Apache HTTP server using the service
    > module.

-   The next five tasks use the lineinfile module to modify the Apache
    > configuration file (/etc/httpd/conf/httpd.conf) to set various
    > HTTP headers. These headers are used to improve the security of
    > the server and protect against various types of attacks.

-   The ServerTokens directive is set to Prod to reduce the amount of
    > information that the server reveals about itself in the Server
    > header.

-   The ServerSignature directive is set to Off to disable the display
    > of the server version and OS in the server-generated pages (e.g.,
    > error pages).

-   The X-Frame-Options header is set to SAMEORIGIN to prevent the
    > server's content from being embedded in a frame or iframe on
    > another site.

-   The X-XSS-Protection header is set to 1; mode=block to enable the
    > browser's built-in XSS protection.

-   The X-Content-Type-Options header is set to nosniff to prevent the
    > browser from MIME-sniffing the content type.

-   The Strict-Transport-Security header is set to max-age=31536000;
    > includeSubDomains to enable HSTS and enforce the use of HTTPS for
    > all subdomains.

-   The final task restarts the Apache HTTP server using the service
    > module to apply the configuration changes.

Overall, this playbook configures various security headers for the
Apache HTTP server on a group of Linux servers. These headers can help
to protect against various types of attacks and improve the overall
security of the server.

#### 

#### **Results**

<img src="media/image12.png" style="width:6.5in;height:4.875in" />

## **Setting up Softwares**

### **Installing Ansible**

To install Ansible on a machine, you will need to have Python installed
on your system. If you don't have Python installed, you can install it
by following the instructions for your operating system:

#### **Linux:**

Most Linux distributions come with Python pre-installed. You can check
if Python is installed on your system by running the following command:

**python3 --version**

If Python is not installed, you can install it using your distribution's
package manager. For example, on Ubuntu, you can use apt-get to install
Python:

**sudo apt-get update**

**sudo apt-get install python3**

#### **MacOS:**

Python is pre-installed on MacOS. You can check if Python is installed
by running the following command:

**python3 --version**

If Python is not installed, you can install it using the brew package
manager:

**brew install python**

#### **Windows:**

To install Python on Windows, you can download the Python installer from
the official Python website
(<https://www.python.org/downloads/windows/>) and run it.

Once you have Python installed, you can install Ansible using pip, the
Python package manager. To install Ansible using pip, open a terminal or
command prompt and run the following command:

**pip install ansible**

This will install the latest version of Ansible. If you want to install
a specific version of Ansible, you can specify the version number by
running the following command:

pip install ansible==2.9

Replace 2.9 with the version number you want to install.

### **Installing Jenkins**

To install Jenkins, you will need to have Java installed on your system.
Jenkins is a Java-based application, so you will need to have a recent
version of Java installed to run it.

You can check if Java is installed on your system by running the
following command:

**java -version**

If Java is not installed, you can install it by following the
instructions for your operating system:

#### **Linux:**

On Linux, you can install Java using your distribution's package
manager. For example, on Ubuntu, you can use apt-get to install Java:

**sudo apt-get update**

**sudo apt-get install default-jdk**

#### **MacOS:**

On MacOS, you can install Java using the brew package manager:

**brew cask install java**

#### **Windows:**

On Windows, you can download the Java installer from the official Java
website (<https://www.java.com/en/download/>) and run it.

Once you have Java installed, you can install Jenkins by following these
steps:

-   Download the latest version of Jenkins from the official Jenkins
    > website (<https://jenkins.io/download/>).

-   Extract the downloaded file to a directory on your machine.

-   Open a terminal or command prompt and navigate to the directory
    > where you extracted Jenkins.

-   Run the following command to start Jenkins:

**java -jar jenkins.war**

This will start the Jenkins server and listen on port 8080. You can
access the Jenkins dashboard by opening a web browser and navigating to
http://localhost:8080.

If you want to run Jenkins as a daemon in the background, you can use
the --daemon flag:

**java -jar jenkins.war --daemon**

You can also specify a different port number using the --httpPort flag:

**java -jar jenkins.war --httpPort=8080**

Replace 8080 with the port number you want to use.

### **Installing OWASP Dependency Check**

OWASP Dependency Check is a tool that helps you identify known
vulnerabilities in the third-party libraries and dependencies that your
project relies on. It can be used to scan your project's dependencies
and generate a report of any vulnerabilities that it finds.

To install OWASP Dependency Check, you will need to have Java installed
on your system. You can check if Java is installed by running the
following command:

**java -version**

If Java is not installed, you can install it by following the
instructions for your operating system:

#### **Linux:**

On Linux, you can install Java using your distribution's package
manager. For example, on Ubuntu, you can use apt-get to install Java:

**sudo apt-get update**

**sudo apt-get install default-jdk**

#### **MacOS:**

On MacOS, you can install Java using the brew package manager:

**brew cask install java**

#### **Windows:**

On Windows, you can download the Java installer from the official Java
website (<https://www.java.com/en/download/>) and run it.

Once you have Java installed, you can install OWASP Dependency Check by
following these steps:

-   Download the latest version of OWASP Dependency Check from the
    > official OWASP website
    > (<https://www.owasp.org/index.php/OWASP_Dependency_Check>).

-   Extract the downloaded file to a directory on your machine.

-   Open a terminal or command prompt and navigate to the directory
    > where you extracted OWASP Dependency Check.

-   Run the following command to scan your project's dependencies:

**dependency-check.sh --project \<project_name> --scan
\<path_to_project>**

Replace \<project_name> with the name of your project and
\<path_to_project> with the path to your project. This will generate a
report in HTML format, which you can view in a web browser.

## **Integrating software with other software**

### **Installing Ansible plugin Jenkins**

To install the Ansible plugin on Jenkins, follow these steps:

-   Log in to the Jenkins dashboard as an administrator.

-   Click on the "Manage Jenkins" menu item, and then click on the
    > "Manage Plugins" option.

-   Click on the "Available" tab.

-   In the "Filter" field, enter "Ansible".

-   Select the "Ansible Plugin" from the list of available plugins.

-   Click on the "Install without restart" button to install the plugin.

Once the plugin is installed, you can use it to run Ansible tasks as
part of your Jenkins builds. To do this, you will need to have Ansible
installed on your Jenkins server. You can install Ansible by following
the instructions in my previous answer.

To use the Ansible plugin, follow these steps:

-   Create a new Jenkins job for your project.

-   In the "Build" section of the job configuration, click on the "Add
    > build step" button and select "Invoke Ansible Playbook".

-   In the "Playbook Path" field, enter the path to your ansible
    > playbook.

-   In the "Inventory" field, enter the path to your inventory file.

-   In the "Limit" field, enter the hosts or host patterns to run the
    > playbook on.

-   Click on the "Save" button to save the job configuration.

When you build the job, the plugin will run your ansible playbook using
the specified inventory and host limit.

### **Installing OWASP Dependency-Check Plugin On Jenkins**

To install the OWASP Dependency Check plugin on Jenkins, follow these
steps:

-   Log in to the Jenkins dashboard as an administrator.

-   Click on the "Manage Jenkins" menu item, and then click on the
    > "Manage Plugins" option.

-   Click on the "Available" tab.

-   In the "Filter" field, enter "OWASP Dependency Check".

-   Select the "OWASP Dependency-Check Plugin" from the list of
    > available plugins.

-   Click on the "Install without restart" button to install the plugin.

Once the plugin is installed, you have to do some more configuration.

-   Download the latest version of OWASP Dependency Check from the
    > official OWASP website
    > (<https://www.owasp.org/index.php/OWASP_Dependency_Check>).

-   Extract the downloaded file to a directory on your Jenkins server.

-   In the Jenkins dashboard, click on the "Manage Jenkins" menu item,
    > and then click on the "Global Tool Configuration" option.

-   Scroll down to the "OWASP Dependency Check" section.

-   In the "Name" field, enter a name for the tool (e.g.
    > "dependency-check").

-   In the "OWASP Dependency Check Home" field, enter the path to the
    > directory where you extracted OWASP Dependency Check.

-   Click on the "Save" button to save the tool configuration.

You can now use the OWASP Dependency Check tool in your Jenkins jobs. To
do this, you will need to add an "Invoke Dependency-Check" build step to
your job and select the tool you just configured from the "Dependency
Check Installation" dropdown menu.

### **Installing Git plugin in Jenkins**

To install the Git plugin on Jenkins, follow these steps:

-   Log in to the Jenkins dashboard as an administrator.

-   Click on the "Manage Jenkins" menu item, and then click on the
    > "Manage Plugins" option.

-   Click on the "Available" tab.

-   In the "Filter" field, enter "Git".

-   Select the "Git Plugin" from the list of available plugins.

-   Click on the "Install without restart" button to install the plugin.

Once the plugin is installed, you can use it to check out code from a
Git repository as part of your Jenkins builds. To do this, you will need
to have Git installed on your Jenkins server.

To install Git on your Jenkins server, follow these steps:

#### **Linux:**

On Linux, you can install Git using your distribution's package manager.
For example, on Ubuntu, you can use apt-get to install Git:

**sudo apt-get update**

**sudo apt-get install git**

#### **MacOS:**

On MacOS, you can install Git using the brew package manager:

**brew install git**

#### **Windows:**

On Windows, you can download the Git installer from the official Git
website (<https://git-scm.com/downloads>) and run it.

To use the Git plugin, follow these steps:

-   Create a new Jenkins job for your project.

-   In the "Source Code Management" section of the job configuration,
    > select "Git" from the "SCM" dropdown menu.

-   In the "Repository URL" field, enter the URL of your Git repository.

-   If your repository requires authentication, click on the "Add"
    > button next to the "Credentials" field and enter your credentials.

-   Click on the "Save" button to save the job configuration.

When you build the job, the plugin will check out the code from your Git
repository and make it available for the rest of the build process.

## **Making all jobs in Jenkins**

**Note: Before making the job first of all add the Web Server IP address
and ssh credentials in the '/etc/ansible/hosts' file as follows**

**\[linux\]**

**192.168.0.100**

**\[linux:vars\]**

**ansible_user=root**

**ansible_password=@Bulb123**

To create a freestyle project in Jenkins to run an Ansible playbook
stored on your local system, follow these steps:

-   In the Jenkins dashboard, click on the "New Item" menu item.

-   Enter a name for your project in the "Item name" field and select
    > "Freestyle project" from the "Kind" dropdown menu.

-   In the "Source Code Management" section, select "None" from the
    > "SCM" dropdown menu.

-   In the "Build" section, click on the "Add build step" button and
    > select "Invoke Ansible Playbook" from the dropdown menu.

-   In the "Playbook Path" field, enter the path to your playbook (e.g.
    > /home/ahmed_pinger/Documents/IEC/Playbooks/Playbook.yml).

-   In the "Inventory" field, enter the path to your inventory file
    > (e.g. /etc/ansible/hosts).

-   In the "Credentials" field, click on the "Add" button and select
    > "Username with password" from the dropdown menu.

-   Enter the username and password for your SSH credentials (e.g. root
    > and @Bulb123).

-   Click on the "Save" button to save the project configuration.

When you build the project, the plugin will run your ansible playbook
using the specified inventory and SSH credentials.

### **Results**

**Repeat the same procedure for all 8 playbooks**

There is a bit of difference between these jobs and the job which is
created for dependency-check. The walkthrough of that job is following.

To create a Jenkins job to do a dependency check on a GitHub repository
using the OWASP Dependency Check plugin, follow these steps:

-   In the Jenkins dashboard, click on the "New Item" menu item.

-   Enter a name for your project in the "Item name" field and select
    > "Freestyle project" from the "Kind" dropdown menu.

-   In the "Source Code Management" section, select "Git" from the "SCM"
    > dropdown menu.

-   In the "Repository URL" field, enter the URL of your GitHub
    > repository.

-   If your repository requires authentication, click on the "Add"
    > button next to the "Credentials" field and enter your credentials
    > if the repo is private.

-   In the "Build" section, click on the "Add build step" button and
    > select "Invoke Dependency-Check" from the dropdown menu.

-   In the "Path to the project" field, enter the path to your project
    > (e.g. .).

-   In the "Dependency Check Installation" field.

The report with the selected format will be stored here

### **Results**

## **Designing the pipeline**

Now we have finally made all of our jobs and our dashboard should have
to be look like this

Now we will be making a pipeline to run all of these playbooks in one
build.

Starting with the pipeline code.
```groovy
pipeline {
    agent any

    stages {
        stage('Performing IaC Checks') {
            steps {
                build 'IaC Checks'
            }
        }

        stage('Cloning Project Repository') {
            steps {
                build 'Cloning'
            }
        }

        stage('httpd Installation') {
            steps {
                build 'HTTPd Installation'
            }
        }

        stage('Applying Setting to Only use HTTP') {
            steps {
                build 'Use Only HTTPS'
            }
        }

        stage('Doing Port Redirection') {
            steps {
                build 'Port Redirection'
            }
        }

        stage('Applying Least Privilage') {
            steps {
                build 'HTTP Least Privilege'
            }
        }

        stage('Activating TLS Listener') {
            steps {
                build 'HTTP TLS listener'
            }
        }

        stage('Applying HTTP Header Security') {
            steps {
                build 'HTTP Header security'
            }
        }

        stage('Performing Dependency Check') {
            steps {
                build 'Perform Dependency Check'
            }
        }
    }
}
```

This is a Jenkins pipeline script that defines a pipeline with nine
stages. Each stage represents a task that the pipeline will perform.

The agent directive specifies that the pipeline can run on any available
Jenkins agent.

The stages block defines the stages of the pipeline. Each stage is
defined by a stage block that contains a steps block with one or more
build steps.

The build steps in the pipeline script are used to trigger the execution
of **Jenkins jobs**. The names of the jobs to be triggered are specified
in single quotes (e.g. build 'IaC Checks').

Here is a description of each stage in the pipeline:

-   "Performing IaC Checks": This stage triggers a Jenkins job that
    > performs infrastructure as code (IaC) checks.

-   "Cloning Project Repository": This stage triggers a Jenkins job that
    > clones the project repository from GitHub.

-   "httpd Installation": This stage triggers a Jenkins job that
    > installs the Apache HTTP server.

-   "Applying Setting to Only use HTTP": This stage triggers a Jenkins
    > job that configures the Apache HTTP server to only use HTTP.

-   "Doing Port Redirection": This stage triggers a Jenkins job that
    > performs port redirection.

-   "Applying Least Privilege": This stage triggers a Jenkins job that
    > applies the least privilege settings to the Apache HTTP server.

-   "Activating TLS Listener": This stage triggers a Jenkins job that
    > activates a TLS listener on the Apache HTTP server.

-   "Applying HTTP Header Security": This stage triggers a Jenkins job
    > that applies HTTP header security settings to the Apache HTTP
    > server.

-   "Performing Dependency Check": This stage triggers a Jenkins job
    > that performs a dependency check using the OWASP Dependency Check
    > plugin.

This pipeline can be executed by running the pipeline job in Jenkins.

## **Testing & Results**

<img src="media/image9.png" style="width:6.5in;height:2.34722in" />

We have a full-stage view of the pipeline where all stages of the
pipeline is executed successfully.

And we have the deployed website as well

<img src="media/image5.png" style="width:6.5in;height:3.04167in" />
