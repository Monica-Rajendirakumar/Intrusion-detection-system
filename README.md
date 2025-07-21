# 🚨 Intrusion Detection System using Machine Learning

This project implements a Machine Learning-powered Intrusion Detection System (IDS) using the **CICFlowMeter** dataset. It is designed to classify network traffic and detect malicious patterns such as port scanning and unauthorized beginnings in packet data.

> 🔐 This system was trained using 78 raw features from CICFlowMeter output data, without column names, and supports real-time classification.

---

## 🧠 Model Architecture

The model was trained on network traffic flow data with labels like `PortScan`, `BENIGN`, etc.  
The dataset contained **78 numerical flow features**, extracted using CICFlowMeter.

- ✅ Trained on: Cleaned and normalized CICFlowMeter `.csv` output
- 📦 Output: `model.pkl` (saved locally after training)

---

## 🚀 Technologies Used

| Component        | Tech Stack                            |
|------------------|----------------------------------------|
| 💻 Programming   | Python 3.10+                          |
| 📚 Libraries     | Pandas, Scikit-learn, WireShark       |
| 🧠 Model         | RandomForestClassifier                |
| 📦 Deployment    | CLI App (Python script)               |
| 🐙 Versioning    | Git + GitHub                          |
| 📊 Dataset       | CICFlowMeter generated data           |

---

## 🛠 How to Start the Project Locally

### 📁 Clone this Repo
- git clone https://github.com/Monica-Rajendirakumar/Intrusion-detection-system.git
- cd Intrusion-Detection-System
  
## 🔧 Install Dependencies
Make sure Python is installed. Then run:
- pip install -r requirements.txt
If requirements.txt isn't available, manually install:
- pip install pandas scikit-learn numpy
  
## 📥 Download Trained Model
Since GitHub doesn't support files over 100MB, the model is hosted externally.

📦 Download model file (model.pkl) here:
🔗 [Download from Huggin Face](https://huggingface.co/chandruganesh00/Intrusion-Detection-RandomForest)

**After downloading:**
- Create a folder in root folder and name it "model"
- Place model.pkl in the project root folder (Intrusion-Detection-System/model).

## ▶️ Run the Detector
Once the model is placed:
- python predict.py

The script will:
- Run and check the network "WiFi" or "Ethernet" (depends on your purpose)
- Print results to terminal

## 📈 Model Accuracy
Metric	Score
Accuracy	98.3%
Class Labels	BENIGN, PORTSCAN
Features Used	78 features (no column names in dataset)

**❗ Notes**
- The input .csv must be raw CICFlowMeter output, where the label (BENIGN, PortScan, etc.) is at the last column of each row.
- The script auto-generates column names as F1, F2, ..., F78.
- This ML project testing video has been givin in github download it and watch.

## 📫 Contact
Developed with 💻 by Monica Rajendirakumar :
- 📧 Mail: monilaks2058@gmail.com.
- 🔗 GitHub: Monica-Rajendirakumar.

⚠️ Disclaimer
This project is strictly for educational and research purposes. Do not use it in production environments without proper validation and testing.

