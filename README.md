# 🛡️ ML-Powered DDoS Shield with Nginx

An automated, intelligent, and containerized security framework designed to identify and mitigate Layer 7 (Application Layer) DDoS attacks using unsupervised Machine Learning. This project replaces static, easily bypassed rate-limiting rules with an adaptive behavioral defense system that continuously profiles incoming traffic to isolate and quarantine malicious actors.

---

## 🚀 Project Overview

Traditional firewalls struggle with volatile web traffic because rigid thresholds cause false positives (blocking real customers) or false negatives (letting subtle attacks pass). 

This project bridges **Cybersecurity, DevOps, and Data Science** by orchestrating an intelligent automated response pipeline. An independent Machine Learning detection service continuously analyzes active connection volumes, applies statistical grouping to discover structural outliers, and automatically registers temporal ban flags into an active caching layer to drop abusive connections at the perimeter.

---

## 🏗️ System Architecture & Workflow

```text
  [ User Traffic ] ---> [ Nginx Gateway ] ---> Shared Volume (/var/log/nginx/access.log)
                              |
       (403 Forbidden if      | (Checks Redis
         IP is banned)        v  for active ban)
                        [ Redis Cache ] <--- [ Python ML Engine ] (Isolation Forest)
