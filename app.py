import streamlit as st
from analyzer import analyze_message
from database import get_connection
import pandas as pd
import plotly.express as px

st.set_page_config(page_title="Monitoramento de Fake News", layout="wide", page_icon="⚠️")

# --------------------------
# Sidebar de Navegação
# --------------------------
page = st.sidebar.selectbox("Navegação", ["📄 Analisar Mensagem", "📊 Dashboard Estatístico"])

# --------------------------
# Página 1: Analisar Mensagem
# --------------------------
if page == "📄 Analisar Mensagem":
    st.title("Analisar Mensagem")

    st.markdown("""
    Este aplicativo analisa mensagens (redes sociais ou normais) para identificar:
    - Golpes digitais  
    - Links suspeitos  
    - Promoções de apostas  
    - Boatos / Fake News  

    Insira abaixo a mensagem para análise.
    """)
    
    text = st.text_area(
        "Ex: Clique aqui no link Aviaozinho, entre outras mensagens suspeitas...", 
        height=180
    )

    if st.button("🔍 Analisar"):
        if text.strip():
            result = analyze_message(text)

            col1, col2 = st.columns(2)
            col1.metric("Nível de Risco", result["risk_level"])
            col2.metric("Pontuação", result["score"])

            st.write("**Tipo de Conteúdo Detectado:**")
            st.info(result["risk_type"])

            st.write("**Padrões Identificados:**")
            for r in result["reasons"]:
                st.write("•", r)

            # ----------------------------
            # Alertas de links
            # ----------------------------
            if result["link_results"]:
                st.subheader("🔗 Status de Links Detectados")
                for link, status in result["link_results"].items():
                    if status == "Perigoso":
                        st.error(f"{link} → {status}")
                    elif status == "Seguro":
                        st.success(f"{link} → {status}")
                    else:
                        st.warning(f"{link} → {status}")

            # ----------------------------
            # Alerta por nível de risco
            # ----------------------------
            if result["risk_level"] == "Alto":
                st.error("⚠️ Esta mensagem apresenta alto risco.")
            elif result["risk_level"] == "Médio":
                st.warning("⚠️ Esta mensagem requer atenção.")
            else:
                st.success("✅ Nenhum padrão crítico identificado.")
        else:
            st.warning("Por favor, insira uma mensagem.")

# --------------------------
# Página 2: Dashboard Estatístico
# --------------------------
elif page == "📊 Dashboard Estatístico":
    st.title("Dashboard Estatístico")
    conn = get_connection()
    df = pd.read_sql("SELECT * FROM logs", conn)
    conn.close()

    if df.empty:
        st.info("Ainda não há análises registradas.")
    else:
        # --------------------------
        # Gráficos
        # --------------------------
        st.subheader("📈 Distribuição de Níveis de Risco")
        fig1 = px.histogram(
            df, x="risk_level", color="risk_level", text_auto=True,
            color_discrete_sequence=px.colors.qualitative.Bold
        )
        st.plotly_chart(fig1, use_container_width=True)

        st.subheader("📊 Distribuição por Tipo de Risco")
        fig2 = px.histogram(
            df, x="risk_type", color="risk_type", text_auto=True,
            color_discrete_sequence=px.colors.qualitative.Prism
        )
        st.plotly_chart(fig2, use_container_width=True)

        st.subheader("📌 Mensagens Registradas")
        st.dataframe(df[["date","message","risk_level","risk_type","score","reasons","link_results"]])
