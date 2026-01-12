import streamlit as st
import pandas as pd
import json
from datetime import datetime
import plotly.express as px
from wordcloud import WordCloud
import matplotlib.pyplot as plt
from text_preprocess import preprocess_ot_text
from streamlit_autorefresh import st_autorefresh

# -------------------------- Auto refresh option (every 10 min) ---------------------------------
count = st_autorefresh(interval=60000, limit=100, key="timer")

# set the title of the page
st.set_page_config(page_title="OT Threat Intel Dashboard", layout="wide")

# to load the data from ../scripts/cve_data.json
# this file contains also the updated data
def load_data():
    try:
        with open("../scripts/cve_data.json", "r") as f:
            raw_data = json.load(f)
        

        list_data = []
        for cve_id, details in raw_data.items():
            details['cve_id'] = cve_id
            
            # parse the date
            details['publish_date'] = pd.to_datetime(details['publish_date'])
            list_data.append(details)

        return list_data
    except:
        st.error("File not found, you can the script to get the data first")
        return []

data = load_data()

# ----------------------------------------- Global filters ----------------------------------
st.sidebar.title("🔍 Global Filters")

# last refresh time
st.sidebar.caption(f"Last updated: {datetime.now().strftime('%H:%M:%S')}")

# searches in CVE-ID or original description
search_query = st.sidebar.text_input("Search CVE-ID or Description", "")

# date filter (from, to)
if data:
    min_date = min(d['publish_date'] for d in data).date()
    max_date = max(d['publish_date'] for d in data).date()
    
    date_from = st.sidebar.date_input("Date From", min_date)
    date_to = st.sidebar.date_input("Date To", max_date)
else:
    date_from, date_to = None, None

# refresh
if st.sidebar.button("🔄 Refresh Data"):
    st.rerun()

# apply filters
filtered_data = [
    d for d in data 
    if (search_query.lower() in d['cve_id'].lower() or search_query.lower() in d['original_description'].lower())
    and (date_from <= d['publish_date'].date() <= date_to)
]

# page navigation filter
page = st.sidebar.selectbox("Go to Page", ["CVE List & Insights", "Analytics & Metrics"])

# -------------------------------- First page (CVE list) ----------------------------------
if page == "CVE List & Insights":
    st.title("🛡️ OT Vulnerability Feed")
    st.write(f"Showing {len(filtered_data)} filtered vulnerabilities.")
    
    for item in filtered_data:
        
        # contains for each CVE
        with st.container():
            st.markdown(f"### {item['cve_id']}  |  📅 *{item['publish_date'].strftime('%Y-%m-%d')}*")
            st.write(f"##### **CVSS: {item['cvss_score']}**")
            st.write(f"**Description:** {item['original_description']}")
            
            # more info button to show ai insights
            with st.expander("✨ Details"):
                st.info(f"**AI Analysis:** {item['ai_response']}")
                
                col1, col2 = st.columns(2)

                with col1:
                  st.markdown("##### 🛡️ Exploitability")

                  if item["metrics"]["exploitabilityScore"]:
                    st.progress(item["metrics"]["exploitabilityScore"]/3.9, text=f"Ease Score: {item['metrics']['exploitabilityScore']}")

                  st.write(f"**Vector:** `{item['metrics']['vector_attack']}`")
                  st.write(f"**Complexity:** `{item['metrics']['vector_complexity']}`")
                  st.write(f"**Privileges:** `{item['metrics']['vector_auth']}`")

                with col2:
                  st.markdown("##### 💥 Impact")

                  if item["metrics"]["impactScore"]:
                    st.progress(item["metrics"]["impactScore"]/6.0, text=f"Damage Score: {item['metrics']['impactScore']}")
                  
                  st.write(f"**Confidentiality:** {item['metrics']['confidentialityImpact']}")
                  st.write(f"**Integrity:** {item['metrics']['integrityImpact']}")
                  st.write(f"**Availability:** {item['metrics']['availabilityImpact']}")

                if item['metrics']['userInteractionRequired'] == "REQUIRED":
                    st.warning("⚠️ **User Interaction Required:** This attack needs a human to click something or take an action.")
                else:
                    st.error("🚀 **Zero-Click Vulnerability:** This can be executed automatically without any user interaction.")
            
            st.markdown("---")

# ----------------------------------- Second page (general analysis) ----------------------------------------------------
elif page == "Analytics & Metrics":
    st.title("📊 Vulnerability Analytics")
    
    if filtered_data:
        df = pd.DataFrame(filtered_data)
        
        # Some metrics at the begining ---------------------------------------------------
        col1, col2, col3 = st.columns(3)
        col1.metric("Total Count", len(df))
        col2.metric("Avg CVSS", round(df['cvss_score'].mean(), 2))
        col3.metric("Critical (9.0+)", len(df[df['cvss_score'] >= 9.0]))

        # timeline (cummulative) (monthly) ---------------------------------------------------
        df_timeline = df.set_index('publish_date').sort_index().resample('MS').size().reset_index(name='Monthly Count')
        df_timeline['Cumulative Count'] = df_timeline['Monthly Count'].cumsum()
        
        fig_cumulative = px.area(
          df_timeline, 
          x='publish_date', 
          y='Cumulative Count',
          labels={'publish_date': 'Timeline', 'Cumulative Count': 'Total Vulnerabilities Found'},
          markers=True,
          template="plotly_dark"
        )

        fig_cumulative.update_traces(fillcolor="rgba(0, 212, 255, 0.3)", line_color="#00d4ff")
        st.plotly_chart(fig_cumulative, use_container_width=True)

        # word cloud on text ---------------------------------------------------
        st.markdown("""
        #### Most imporant mentioned words in CVEs' descriptions
        """)

        text = " ".join(desc for desc in df.original_description + df.ai_response)
        text = preprocess_ot_text(text)

        wordcloud = WordCloud(
        background_color="black",
        mode="RGBA",
        width=800, 
        height=400,
        colormap="YlOrRd"
    ).generate(text)

        
        fig, ax = plt.subplots(figsize=(8, 4), dpi=1000)
        ax.imshow(wordcloud, interpolation='bilinear')
        ax.axis("off")
        st.pyplot(fig)
        
        # extract data from metrics 
        metrics_df = pd.json_normalize(df['metrics'])
        df = df.join(metrics_df)

        col1, col2 = st.columns([1, 1])

        with col1:
            # Histogram for CVSS ---------------------------------------------------
            fig = px.histogram(df, x="cvss_score", nbins=10, title="Distribution of CVSS Scores",
                            labels={"cvss_score": "CVSS Score"})
            st.plotly_chart(fig)
        
        with col2:
            cvss =  df['cvss_score'].fillna(df['cvss_score'].mean())

            # scatter plot, exploitabilityScore vs impactScore ---------------------------------------------------
            fig = px.scatter(df, x="exploitabilityScore", y="impactScore",
                    color=cvss, size=cvss,
                    color_continuous_scale="RdYlGn_r",
                    hover_data=["cvss_score"],
                    title="Impact vs Exploitability of CVEs")

            st.plotly_chart(fig)

        # dist of attack vector ---------------------------------------------------
        attack_vector_grouped = df.groupby("vector_attack").size().reset_index(name="count")

        fig = px.bar(
        attack_vector_grouped,
            x="vector_attack",
            y="count",
            color="count",                     
            text="count",                       
            title="Number of CVEs by Attack Vector",
            color_continuous_scale="Viridis" 
        )

        st.plotly_chart(fig)


    else:
        st.warning("No data matches the selected filters.")