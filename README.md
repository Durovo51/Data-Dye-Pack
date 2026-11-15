<a id="readme-top"></a>

<br />
<div align="center">
  <h3 align="center">Data Dyepack</h3>

  <p align="center">
    <strong>Let them dig. Everything they take comes out stained.</strong>
    <br />
    Built for the MadHacks 2026 TDS Privacy and Security Challenge.
    <br />
    <br />
    <a href="https://durovo51.github.io/Data-Dye-Pack/index.html"><strong>Explore the website »</strong></a>
    <br />
    <br />
    <a href="https://www.youtube.com/watch?v=5LePHZaZZ3o">View Demo</a>
    ·
    <a href="https://github.com/Durovo51/Data-Dye-Pack/issues">Report Issue</a>
  </p>
</div>

<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#what-it-does">What It Does</a></li>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li>
      <a href="#usage">Usage</a>
      <ul>
        <li><a href="#the-demo-in-one-minute">The Demo in One Minute</a></li>
        <li><a href="#databricks-integration">Databricks Integration</a></li>
      </ul>
    </li>
    <li><a href="#roadmap--honest-limits">Roadmap & Honest Limits</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
    <li><a href="#acknowledgments">Acknowledgments</a></li>
  </ol>
</details>

---

## About The Project

When an AI agent breaks into a company, it does not read one table. It reads everything. **Data Dyepack** plants dye packs in that data, stoping the agent in it's tracks, containing it on contact. Canary customers bait AI agents and bait files sound the alarm the moment a thief or AI agent touches them. Every customer file on the drive locks in half a second, the team's phone gets the alert and a stolen copy opens to convincing fakes.

### What It Does

* **Canary customers:** Fake customers are mixed into the real table and kept on a separate watch list. No real person or app ever touches one, so a touch at machine speed or any use of one (a login, an email, a call) is a true alarm. A canary travels with stolen data, so it fires even days later, wherever the copy went, and the alarm names that copy.
* **A decoy drive:** A company drive holds decoy files among the real ones, like an `"all customers full export"` and an `"unencrypted backup"`. No real workflow opens them, so any read is a strong signal.
* **Lock in place:** When a decoy is read, Dyepack honey-locks every customer file on the whole drive where it sits. `customers.csv` becomes `customers.csv.dye`. The company's own apps fail loudly and one command puts every file back byte for byte.
* **Honey encryption:** A stolen `.dye` file opens to a believable fake customer list for every wrong password, so a thief can never tell which guess was right. The real list is the only one that carries the canaries.
* **A speed alarm:** Anything reading over 600 customers a minute is machine speed. A person can't read that fast. The alarm counts per login and per address, so a stolen login cannot dodge it by reconnecting.
* **A live dashboard:** Every alarm lands on a console with a plain English report, a read speed chart, the time to containment, a phone push, and a message talking about the breach. The report and triage are written by a model served on Databricks.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

### Built With

* [![Python][Python.org]][Python-url] (3.10+ Standard Library — zero third-party packages required)
* [![Databricks][Databricks.com]][Databricks-url] (Served Chat Model, Delta Tables & Genie)
* [![SQLite][SQLite.org]][SQLite-url] (Customer tables along with CSV & JSON)
* [![Linux][Linux.org]][Linux-url] (`inotify` / `auditd` filesystem watcher)
* [![macOS][Apple.com]][Apple-url] (System event stream watcher)

<p align="right">(<a href="#readme-top">back to top</a>)</p>

---

## Getting Started

Follow these steps to get a local lab environment and demo drill up and running.

### Prerequisites

* **Python 3.10 or newer.** No third-party packages are required.
  ```sh
  python3 --version
  ```

### Installation

1. Clone the repository:
   ```sh
   git clone [https://github.com/Durovo51/data-dyepack.git](https://github.com/Durovo51/data-dyepack.git)
   cd data-dyepack
   ```
2. Install the package in editable mode:
   ```sh
   pip install -e .
   ```
3. Initialize the lab, seed the database with real and canary records, and set up the decoy drive:
   ```sh
   dyepack lab && dyepack seed && dyepack drive
   ```
4. Copy `.env.example` to `.env` and set a lock password:
   ```sh
   cp .env.example .env
   ```
   Inside `.env`:
   ```env
   DYEPACK_LOCK_PASSWORD=pick-any-phrase-you-will-remember
   ```

<p align="right">(<a href="#readme-top">back to top</a>)</p>

---

## Usage

1. **Start the server and open the live dashboard:**
   ```sh
   dyepack serve
   ```
2. **Run the interactive demo drills:**
   ```sh
   dyepack drill heist
   dyepack drill agent
   ```
3. **Watch the whole file system live:**
   Run the watcher alongside the server.
   ```sh
   sudo dyepack sentinel
   ```
   > **Note:** On **macOS**, `sentinel` reads the system event stream and requires **Full Disk Access** for your terminal plus `sudo`. On **Linux**, it uses `inotify` and needs no root. For the full Linux server walkthrough, refer to [`docs/linux-server-demo.md`](docs/linux-server-demo.md).

### The Demo in One Minute

1. **Baseline:** A normal day of support work raises zero alarms.
2. **Speed Alarm & Lockout:** A phished support login reads customers in bulk. Caught and locked after two pages (about 200 rows out) in under a second.
3. **Honey Encryption Test:** The thief steals an export and cracks it. Every one of fifty wrong passwords opens a believable fake list, and the served model cannot pick the real one out of five.
4. **Canary Tracking:** The thief uses a stolen login. The alarm fires and names the exact export it came from.
5. **AI Agent Containment:** An AI agent is pointed at the company drive. It trips a decoy in a few hundredths of a second, the whole drive locks in place, the phone buzzes, and the agent is left with locked files and fakes.

### Databricks Integration

Reports and the triage card are written by a chat model served on Databricks, and the alarm history lands in Delta tables for a dashboard and Genie questions.

To enable Databricks features, copy `.env.example` to `.env` and fill in your workspace details:
* Host
* Warehouse
* Model
* Token

*Without these credentials, reports automatically fall back to a built-in template and the rest of the demo runs identically.*

<p align="right">(<a href="#readme-top">back to top</a>)</p>

---

## Roadmap & Honest Limits

Data Dyepack is designed with clear boundaries between the single-laptop hackathon lab and a production deployment:

- [ ] **Production-owned canary endpoints:** In the lab, every customer is made up. In production, canary emails and phone numbers are ones the company owns, so a thief who reaches out lands on the company, never on a stranger.
- [ ] **External Key Management & Dual Control:** In the lab, the lock password sits in `.env` so the demo runs on one laptop. In production, it lives in a key manager on a separate system and unlocking takes two people.
- [ ] **Population-Model Headers for Honey Encryption:** Honey encryption hides the real list only as well as its header matches where the data really came from. A real company needs a header from a population model, not from the list being locked.
- [ ] **Expanded File Type & Process Matching:** Lock in place currently covers customer tables (`CSV`, `JSON`, `SQLite`), not arbitrary files. The sentinel on Linux sees the file but not the program, so registered tools are matched on macOS or through the `auditd` agent.
- [ ] **Post-First-Read Containment Scope:** Dyepack names everything an agent read before the lock. It does not claim to stop the first read—it makes everything after it worthless and marks what left.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## License

Distributed under the MIT License. See `LICENSE` for more information.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

---

## Contact

* * **Jake Bryant**: [Github](https://github.com/Durovo51) - [LinkedIn](https://www.linkedin.com/in/jake-bryant-079484330/)
 
* * **Anand Indukuri**: [Github](https://github.com/anandindukuri-hub) - [LinkedIn](https://www.linkedin.com/in/anandindukuri/)
 
* * **Mark Oskin**: [Github](https://github.com/moskin-cpu) - [LinkedIn](https://www.linkedin.com/in/mark-oskin-33aa20303/)

<p align="right">(<a href="#readme-top">back to top</a>)</p>

---

## Acknowledgments

* Built for the **MadHacks 2026 TDS Privacy and Security Challenge**
* [Databricks](https://www.databricks.com/) (Model Serving, Delta Tables, and Genie)
* [Best-README-Template](https://github.com/othneildrew/Best-README-Template)
* [Img Shields](https://shields.io)

<p align="right">(<a href="#readme-top">back to top</a>)</p>

[Python.org]: https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white
[Python-url]: https://www.python.org/
[Databricks.com]: https://img.shields.io/badge/Databricks-FF3621?style=for-the-badge&logo=databricks&logoColor=white
[Databricks-url]: https://www.databricks.com/
[SQLite.org]: https://img.shields.io/badge/SQLite-003B57?style=for-the-badge&logo=sqlite&logoColor=white
[SQLite-url]: https://www.sqlite.org/
[Linux.org]: https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black
[Linux-url]: https://www.kernel.org/
[Apple.com]: https://img.shields.io/badge/macOS-000000?style=for-the-badge&logo=apple&logoColor=white
[Apple-url]: https://www.apple.com/macos/
