# Detector_de_Anomalii_in_Log-uri_cu_ML_Simplu

## Descriere
Acest proiect propune un sistem de detecție a anomaliilor în log-uri de autentificare web, în contextul securității aplicațiilor cloud. Obiectivul este identificarea atacurilor de tip brute-force prin utilizarea tehnicilor de machine learning nesupravegheat.

---

## Obiectiv
Detectarea comportamentelor suspecte în log-uri fără utilizarea unor date etichetate, prin analiza tiparelor de acces.

---

## Abordare
Sistemul urmează următorul pipeline:

1. Generare log-uri sintetice (utilizatori normali + atacator)
2. Agregare date la nivel de IP
3. Extracție de caracteristici (feature engineering):
   - număr total de request-uri
   - număr de autentificări eșuate
   - rata de eșec (fail_rate)
4. Aplicarea algoritmului Isolation Forest
5. Detectarea anomaliilor și generarea de alerte
6. Vizualizarea rezultatelor

---

## Tehnologii utilizate
- Python
- pandas
- scikit-learn
- matplotlib

---

## Model utilizat
- **Isolation Forest**
- Algoritm nesupravegheat de detecție a anomaliilor
- Identifică comportamente rare în loc de semnături cunoscute de atac

---

## Output
Sistemul generează:
- `results.csv` – rezultate detecție
- `anomaly_plot.png` – vizualizare anomalii sub forma unui grafic

---

## Rulare proiect

```bash
pip install -r requirements.txt
python3 src/main.py
