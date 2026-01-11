# This file to preprocess text for wordcloud visual

import nltk
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer
import re

# check libs are installed (faster than trying to download each time)
try:
    nltk.data.find('corpora/stopwords')
except LookupError:
    nltk.download('stopwords')

try:
    nltk.data.find('corpora/wordnet')
except LookupError:
    nltk.download('wordnet')

def preprocess_ot_text(text):
    # init stop words like (an, the, etc)
    stop_words = set(stopwords.words('english'))
    
    # noise words
    cve_noise = {
        'vulnerability', 'vulnerabilities', 'discovered', 'determined', 'affected',
        'impacts', 'unknown', 'manipulation', 'results', 'cause', 'causes',
        'attack', 'may', 'initiated', 'utilize', 'utilized', 'disclosed', 
        'disclosure', 'early', 'contacted', 'respond', 'way', 'identified',
        'file', 'component', 'software', 'version', 'issue', 'allow'
    }
    stop_words.update(cve_noise)
    
    
    lemmatizer = WordNetLemmatizer()
    
    # remoev noise chars
    text = re.sub(r'[^a-zA-Z\s]', '', text).lower()
    
    words = text.split()
    filtered_words = [lemmatizer.lemmatize(w) for w in words if w not in stop_words]
    
    return " ".join(filtered_words)