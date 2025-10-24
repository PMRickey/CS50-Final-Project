# Medication Tracker

#### Video Demo  
https://youtu.be/cIUqQ-yRMe4  

#### Description  
The Flask-based web app helps users keep track of their medications and check for duplicates. In addition, it validates drugs with RxNorm, retrieves side effect information from the FDA, flags unverified entries, and lets users archive or restore medications. Security features are included throughout the app.  

---

### Features  

The application supports secure registration and login. Passwords are hashed using industry-standard encryption for security, and users can add medications, view them, archive drugs they no longer need, or unarchive medicines they want to keep active, while keeping their medication record intact.  

Medications are validated against NIH’s RxNorm database to ensure accuracy, and the app retrieves side effect information from the OpenFDA database and fills it in automatically. For security, the app logs out users after 15 minutes of inactivity, with a warning shown before the session ends. All sensitive medical data is encrypted at rest using the **Python cryptography library**. Passwords are protected with Werkzeug’s hashing functionality, and encryption keys are stored in environment variables so th...

---

### Design Philosophy  

The design of the application emphasizes accessibility and ease of use. It was created with seniors in mind, using large text, clearly labeled buttons, and high-contrast colors that make the interface easy to navigate. A modern look is achieved with gradient backgrounds, card-based layouts, and responsive design choices that adapt to different devices. Overall, the interface balances a friendly appearance with the clarity and simplicity needed for users over 70 years old.  

---

### Technical Details  

**Database Schema**  

- **users** – Stores user accounts for authentication.  
  - `id`: Primary key  
  - `username`: Unique username  
  - `hash`: Password hash  

- **medications** – Tracks medications for each user.  
  - `id`: Primary key  
  - `user_id`: References `users(id)`  
  - `name`: Medication name  
  - `dosage`: Dosage information  
  - `frequency`: Frequency of use  
  - `purpose`: Stated purpose of medication  
  - `side_effects`: Listed side effects  
  - `notes`: User notes  
  - `info_last_updated`: Timestamp of last info update  
  - `verified`: Flag for RxNorm verification (0 = unverified, 1 = verified)  
  - `purpose_auto`: Flag indicating if purpose was auto-filled (0/1)  
  - `side_effects_auto`: Flag indicating if side effects were auto-filled (0/1)  
  - `active`: Status flag (1 = active, 0 = archived)  

- **drug_reference** – Stores cached drug information from RxNorm.  
  - `id`: Primary key  
  - `drug_name`: Unique drug name  
  - `active_ingredient`: Main active ingredient  
  - `rxcui`: RxNorm Concept Unique Identifier  
  - `source`: Default is "RxNorm"  
  - `date_added`: Timestamp of when the entry was created  

- **drug_ingredients** – Maps drugs to their active ingredients.  
  - `id`: Primary key  
  - `drug_name`: Medication name  
  - `ingredient`: Active ingredient  
  - `UNIQUE(drug_name, ingredient)`: Prevents duplicates  

**APIs Used**  
- [RxNorm API](https://rxnav.nlm.nih.gov/) – NIH medication validation  
- [OpenFDA API](https://api.fda.gov/) – FDA drug label and side effects data  

---

### File Overview  

- **app.py** – Main Flask application containing routes, authentication logic, database connections, and encryption routines.  
- **templates/** – HTML templates for the application, including `base.html` (layout), `login.html`, `register.html`, `add_medication.html`, and `list_medications.html`.  
- **static/** – Static assets such as `style.css` for design and `pill-bottles.jpg` for the background watermark.  
- **med.db** – SQLite database storing all user accounts and medication data.  
- **README.md** – Project documentation (this file).  

---

### Python Version Requirement  

**Important:** This application requires **Python 3.12** for full functionality.  

- **Issue with Python 3.13:** 
  The automatic database encryption on shutdown does not work properly due to changes in signal handling.  

- **Workaround:** 
  Encryption functions still work correctly when called manually, but the automatic `Ctrl+C` shutdown process fails under Python 3.13.  

- **Recommendation:** 
  Run the application with Python 3.12 for testing and demonstration.  

Example setup:  
```bash
py -3.12 -m pip install Flask Werkzeug requests cryptography
py -3.12 app.py

---

### Design Decisions  

- **Why Flask?**  
  Flask was chosen for its simplicity and CS50 course familiarity while still providing enough power for a full-featured web application.  

- **Why `base.html` Instead of `layout.html`?**  
  Early versions followed the CS50 convention of using `layout.html` as the master template. Later, it was renamed to `base.html` to align with common Flask practices and better reflect its role as the parent template for all other pages.  

- **Why Cryptography Instead of SQLCipher?**  
  There was an attempt to use SQLCipher for database encryption, but Windows compilation issues made it difficult to set up. To ensure smooth development and cross-platform compatibility, the Python **cryptography** library was chosen instead. It provides reliable AES encryption and integrates cleanly with the project.  

- **Why Duplicate Detection Only?**  
  The CS50 version focuses on duplicate name detection to keep the code manageable. A full version could expand to ingredient overlap.  

- **Why Senior-Friendly Design?**  
  Large fonts, high contrast, big buttons, and tabular layouts help older users read, compare, and manage medications easily.  

- **Why Table vs. Card Layout?**  
  A table format allows all medications to be seen at once, compared side-by-side, and printed in a familiar style.  


---

### Known Limitations  

The CS50 version omits password resets, archived medication viewing, reminders, and drug interaction checks. Some API results may be incomplete due to RxNorm or OpenFDA coverage.  

---

### Future Enhancements  

- Reminders  
- Caregiver Access  
- Mobile Apps  
- Analytics Dashboard  
- Freemium Business Model  

---

### Lessons Learned  

Working on this project gave me a stronger understanding of how **HTML, CSS, and Flask (app.py)** interact with each other. One of my biggest challenges was styling. At first, none of the changes I made to the CSS file seemed to apply. After spending an hour trying to troubleshoot on my own, I asked AI for help and was introduced to the **browser’s Developer Tools**.  

I learned that I could press **F12** to open the Dev Tool, see which CSS rules were actually applied, and notice when my intended rules were crossed out. This taught me that while I can write CSS the way I want, the browser ultimately decides which rules to apply. By checking the applied rules in real time, I was able to adjust the correct parts of the CSS file and achieve the layout and design I wanted.  

In working through styling, I also realized just how many CSS properties exist. I knew some of the common properties, but not all of them, and there are far too many to memorize. With AI’s guidance, I learned about parameters I hadn’t seen before, which helped me fine-tune the interface the way I envisioned.

---

### Credits & Acknowledgments  

Developer: Pauline Rickey  
Course: CS50x – Introduction to Computer Science  
APIs: NIH RxNorm, OpenFDA  
Frameworks: Flask, Werkzeug, Cryptography  
Design: Tailwind CSS color palette inspiration  
Icons: Emoji icons for simplicity and clarity  

AI Assistance: Claude (Anthropic) and ChatGPT (OpenAI) were used for debugging assistance, code review, technical guidance, and problem-solving support. All code was written, understood, tested, and implemented by the developer. AI tools served as educational resources.  

---

### License & Disclaimer  

© 2025 Pauline Rickey. All rights reserved.  

**Medical Disclaimer:** This medication tracker is a personal organizational tool only. It is **not** a substitute for professional medical advice, diagnosis, or treatment. Always seek the advice of a physician or qualified health provider with any questions about medications or medical conditions.  

---

### Dedication  

This project is dedicated to my **Dad**, whose love and strength continue to guide me.  

---

### For CS50 Graders  

The application demonstrates secure medical data handling, API integration, user authentication,  
and senior-focused UX design. Encryption is implemented with the Python cryptography library;  
keys are managed through environment variables.  

Note: The Python version requirement (3.12 for automatic encryption on shutdown) does not affect  
grading. The CS50 environment (Python 3.10/3.11) runs the application normally, and all core  
functionality — registration, login, medication management, RxNorm/OpenFDA integration, and  
session security — works as intended. The unencrypted `med.db` is included for grading.
