"""
app.py
Interface Streamlit — Monitor de Phishing & Fake News
"""

import streamlit as st
from analyzer import analyze_message
from database import (
    get_connection, lookup_phone, get_top_suspicious_numbers,
    save_feedback, add_to_blacklist, remove_from_blacklist,
    get_blacklist, get_feedback_stats, is_blacklisted
)
import pandas as pd
import plotly.express as px
import os
import io
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

st.set_page_config(
    page_title="Monitor de Phishing & Fake News",
    layout="wide",
    page_icon="⚠️"
)

if not os.getenv("GOOGLE_SAFE_BROWSING_API_KEY"):
    st.sidebar.warning(
        "⚠️ API Key do Google Safe Browsing não configurada.\n\n"
        "Cria um ficheiro `.env` com `GOOGLE_SAFE_BROWSING_API_KEY=a_tua_chave`."
    )

page = st.sidebar.selectbox(
    "Navegação",
    ["📄 Analisar Mensagem", "🔎 Pesquisar Número", "📊 Dashboard Estatístico"]
)


# ============================================================
# FUNÇÃO: Gerar PDF de relatório
# ============================================================
def generate_pdf(result: dict, message: str, phone_number: str = None) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=50, rightMargin=50, topMargin=50, bottomMargin=50)
    styles = getSampleStyleSheet()
    story = []

    title_style = ParagraphStyle("title", parent=styles["Title"], fontSize=18, spaceAfter=6, textColor=colors.HexColor("#1F3864"))
    heading_style = ParagraphStyle("heading", parent=styles["Heading2"], fontSize=12, spaceAfter=4, textColor=colors.HexColor("#1F3864"))
    normal_style = ParagraphStyle("normal", parent=styles["Normal"], fontSize=10, spaceAfter=4)
    small_style = ParagraphStyle("small", parent=styles["Normal"], fontSize=9, textColor=colors.HexColor("#666666"))

    story.append(Paragraph("Relatório de Análise de Mensagem", title_style))
    story.append(Paragraph("Sistema de Detecção de Links Maliciosos em Mensagens Digitais", small_style))
    story.append(Spacer(1, 6))
    story.append(Paragraph(f"Data de análise: {datetime.now().strftime('%d/%m/%Y às %H:%M:%S')}", small_style))
    story.append(Spacer(1, 14))

    story.append(Paragraph("Mensagem Analisada", heading_style))
    story.append(Paragraph(message[:600] + ("..." if len(message) > 600 else ""), normal_style))
    story.append(Spacer(1, 8))

    if phone_number:
        story.append(Paragraph(f"Número que enviou a mensagem: {phone_number}", normal_style))
        story.append(Spacer(1, 8))

    story.append(Paragraph("Resultado da Análise", heading_style))
    data = [
        ["Campo", "Valor"],
        ["Nível de Risco", result.get("risk_level", "-")],
        ["Tipo de Conteúdo", result.get("risk_type", "-")],
        ["Pontuação", str(result.get("score", 0))],
        ["Número na Blacklist", "Sim" if result.get("blacklisted") else "Não"],
    ]
    t = Table(data, colWidths=[200, 280])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F3864")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f2f2f2"), colors.white]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(t)
    story.append(Spacer(1, 12))

    story.append(Paragraph("Padrões Detectados", heading_style))
    reasons = result.get("reasons", [])
    if reasons:
        for r in reasons:
            story.append(Paragraph(f"• {r}", normal_style))
    else:
        story.append(Paragraph("Nenhum padrão suspeito detectado.", normal_style))
    story.append(Spacer(1, 12))

    link_results = result.get("link_results", {})
    if link_results:
        story.append(Paragraph("Links Verificados", heading_style))
        for link, link_data in link_results.items():
            if isinstance(link_data, dict):
                status = link_data.get("status", "Desconhecido")
            else:
                status = str(link_data)
            story.append(Paragraph(f"• {link} → {status}", normal_style))
        story.append(Spacer(1, 12))

    meta = result.get("meta", {})
    if meta:
        story.append(Paragraph("Análise Detalhada do Texto", heading_style))
        meta_data = [
            ["Indicador", "Valor"],
            ["Proporção de maiúsculas", f"{int(meta.get('uppercase_ratio', 0) * 100)}%"],
            ["Pontos de exclamação", str(meta.get("exclamations", 0))],
            ["Emojis detectados", str(meta.get("emojis", 0))],
            ["Scripts mistos", "Sim" if meta.get("mixed_scripts") else "Não"],
        ]
        t2 = Table(meta_data, colWidths=[200, 280])
        t2.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F3864")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f2f2f2"), colors.white]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("PADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(t2)
        story.append(Spacer(1, 12))

    story.append(Paragraph("Alerta Educativo", heading_style))
    story.append(Paragraph(result.get("educational_alert", ""), normal_style))
    story.append(Spacer(1, 16))

    story.append(Paragraph("___________________________________________", small_style))
    story.append(Paragraph("Relatório gerado automaticamente pelo Sistema de Detecção de Links Maliciosos em Mensagens Digitais.", small_style))
    story.append(Paragraph("Este documento destina-se exclusivamente a fins informativos e educativos.", small_style))

    doc.build(story)
    buffer.seek(0)
    return buffer.read()


# ============================================================
# PÁGINA 1: Analisar Mensagem
# ============================================================
if page == "📄 Analisar Mensagem":
    st.title("🔍 Analisar Mensagem")

    st.markdown("""
    Analisa mensagens para identificar golpes digitais, links suspeitos,
    promoções de apostas e fake news.
    """)

    tab1, tab2 = st.tabs(["✍️ Texto", "🖼️ Imagem (OCR)"])

    with tab1:
        text = st.text_area(
            "Cole aqui a mensagem suspeita...",
            placeholder="Ex: URGENTE! Clique agora no link bit.ly/xxxxx e confirme os seus dados!",
            height=180,
        )

    with tab2:
        uploaded = st.file_uploader("Carrega uma imagem com a mensagem suspeita", type=["png", "jpg", "jpeg"])
        text_from_image = ""
        if uploaded:
            try:
                from PIL import Image, ImageFilter, ImageEnhance
                import pytesseract

                image = Image.open(uploaded)
                st.image(image, caption="Imagem carregada", width=400)

                # Pré-processamento para melhorar OCR em imagens escuras (ex: WhatsApp dark mode)
                # 1. Converte para escala de cinzento
                gray = image.convert("L")

                # 2. Aumenta contraste
                gray = ImageEnhance.Contrast(gray).enhance(2.5)

                # 3. Aumenta nitidez
                gray = gray.filter(ImageFilter.SHARPEN)

                # 4. Redimensiona para melhor leitura (Tesseract prefere imagens maiores)
                w, h = gray.size
                gray = gray.resize((w * 2, h * 2), Image.LANCZOS)

                # 5. Tenta extrair com português e inglês
                config = "--oem 3 --psm 6"
                text_from_image = pytesseract.image_to_string(gray, lang="por+eng", config=config)

                # Limpa texto extraído
                text_from_image = "\n".join(
                    line.strip() for line in text_from_image.splitlines()
                    if len(line.strip()) > 3
                )

                if text_from_image.strip():
                    st.success("✅ Texto extraído da imagem:")
                    st.code(text_from_image)
                else:
                    st.warning("⚠️ Não foi possível extrair texto. Tenta com uma imagem mais nítida ou cola o texto manualmente no separador Texto.")

            except ImportError:
                st.warning("⚠️ OCR não disponível neste ambiente. Usa o site online para analisar imagens.")
            except Exception as e:
                st.warning(f"⚠️ Erro ao processar imagem: {e}. Tenta colar o texto manualmente no separador Texto.")

        if text_from_image:
            text = text_from_image
        elif "text" not in dir():
            text = ""

    phone_number = st.text_input(
        "📱 Número que enviou a mensagem (opcional)",
        placeholder="Ex: +258 84 123 4567",
        help="Regista o número para identificá-lo em análises futuras.",
    )

    if st.button("🔍 Analisar"):
        final_text = text if text.strip() else text_from_image if "text_from_image" in dir() else ""

        if final_text.strip():
            with st.spinner("A analisar..."):
                result = analyze_message(final_text, phone_number=phone_number.strip() or None)

            if result.get("blacklisted"):
                st.error(f"🚫 ATENÇÃO: O número **{phone_number}** está na blacklist de números confirmadamente perigosos!")

            col1, col2, col3 = st.columns(3)
            col1.metric("Nível de Risco", result["risk_level"])
            col2.metric("Pontuação", result["score"])
            col3.metric("Tipo de Conteúdo", result["risk_type"])

            if phone_number.strip():
                phone_data = lookup_phone(phone_number.strip())
                if phone_data and phone_data["reputation"]["report_count"] > 1:
                    count = phone_data["reputation"]["report_count"]
                    st.warning(f"📵 O número **{phone_number}** já foi reportado **{count}x** como: *{phone_data['reputation']['risk_type']}*")
                else:
                    st.info(f"📱 Número {phone_number} registado pela primeira vez.")

            st.subheader("🚩 Padrões Identificados")
            if result["reasons"]:
                for r in result["reasons"]:
                    st.write("•", r)
            else:
                st.write("Nenhum padrão suspeito detectado.")

            with st.expander("🔬 Análise detalhada do texto"):
                meta = result.get("meta", {})
                m1, m2, m3, m4 = st.columns(4)
                m1.metric("Maiúsculas", f"{int(meta.get('uppercase_ratio', 0) * 100)}%")
                m2.metric("Exclamações", meta.get("exclamations", 0))
                m3.metric("Emojis", meta.get("emojis", 0))
                m4.metric("Scripts mistos", "Sim ⚠️" if meta.get("mixed_scripts") else "Não")

            if result["link_results"]:
                st.subheader("🔗 Links Detectados")
                for link, link_data in result["link_results"].items():
                    if isinstance(link_data, dict):
                        status = link_data.get("status", "Desconhecido")
                        threat = link_data.get("threat_type", "")
                        is_wa = link_data.get("whatsapp_phishing", False)
                    else:
                        status = link_data
                        threat = ""
                        is_wa = False

                    if status == "Perigoso":
                        st.error(f"🔴 **PERIGOSO** — {link}\n\n⚠️ Ameaça confirmada pelo Google Safe Browsing: `{threat}`")
                    elif is_wa:
                        st.error(f"🟠 **SUSPEITO — WhatsApp Phishing** — {link}\n\nEste tipo de link é usado para roubar dados via WhatsApp. Não cliques!")
                    elif "Suspeito" in str(status):
                        st.warning(f"🟡 Suspeito — {link} → {status}")
                    elif status == "Seguro":
                        st.success(f"🟢 Seguro — {link}")
                    else:
                        st.warning(f"🟡 {link} → {status}")

            st.subheader("📢 Avaliação Final")
            if result["risk_level"] == "Alto":
                st.error("🚨 ALTO risco. Não clique em links nem partilhe dados pessoais.")
            elif result["risk_level"] == "Médio":
                st.warning("⚠️ Requer atenção. Verifique a fonte antes de agir.")
            elif result["risk_level"] == "Baixo":
                st.info("ℹ️ Risco baixo. Mantenha-se cauteloso.")
            else:
                st.success("✅ Nenhum padrão crítico identificado.")

            with st.expander("📚 Dica de Segurança"):
                st.info(result["educational_alert"])

            st.subheader("📄 Exportar Relatório")
            pdf_bytes = generate_pdf(result, final_text, phone_number.strip() or None)
            st.download_button(
                label="⬇️ Descarregar Relatório PDF",
                data=pdf_bytes,
                file_name=f"relatorio_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                mime="application/pdf",
            )

            st.subheader("💬 Esta análise foi correcta?")
            col_f1, col_f2 = st.columns(2)
            log_id = result.get("log_id")

            with col_f1:
                if st.button("✅ Sim, está correcta"):
                    save_feedback(log_id, correct=True)
                    st.success("Obrigado pelo feedback!")

            with col_f2:
                if st.button("❌ Não, está errada"):
                    comment = st.text_input("O que estava errado? (opcional)")
                    save_feedback(log_id, correct=False, comment=comment)
                    st.warning("Feedback registado. Vamos melhorar!")

            if phone_number.strip():
                st.subheader("🚫 Blacklist")
                if is_blacklisted(phone_number.strip()):
                    st.warning(f"O número {phone_number} já está na blacklist.")
                    if st.button("🗑️ Remover da blacklist"):
                        remove_from_blacklist(phone_number.strip())
                        st.success("Removido da blacklist.")
                else:
                    if st.button("🚫 Adicionar número à blacklist"):
                        reason = st.text_input("Motivo (opcional)", key="bl_reason")
                        add_to_blacklist(phone_number.strip(), reason)
                        st.success(f"Número {phone_number} adicionado à blacklist!")

        else:
            st.warning("Por favor, insira uma mensagem ou carregue uma imagem.")


# ============================================================
# PÁGINA 2: Pesquisar Número
# ============================================================
elif page == "🔎 Pesquisar Número":
    st.title("🔎 Pesquisar Número de Telefone")

    search_number = st.text_input("Introduz o número a pesquisar", placeholder="Ex: +258 84 123 4567")

    if st.button("🔍 Pesquisar"):
        if search_number.strip():
            if is_blacklisted(search_number.strip()):
                st.error(f"🚫 O número **{search_number}** está na **blacklist** de números confirmadamente perigosos!")

            data = lookup_phone(search_number.strip())

            if data is None:
                st.success(f"✅ O número **{search_number}** não tem registos suspeitos neste sistema.")
            else:
                rep = data["reputation"]

                if rep["risk_level"] == "Alto":
                    st.error(f"🚨 Número de ALTO RISCO — reportado {rep['report_count']}x")
                elif rep["risk_level"] == "Médio":
                    st.warning(f"⚠️ Número suspeito — reportado {rep['report_count']}x")
                else:
                    st.info(f"ℹ️ Número com registos — reportado {rep['report_count']}x")

                col1, col2, col3, col4 = st.columns(4)
                col1.metric("Nível de Risco", rep["risk_level"])
                col2.metric("Tipo de Fraude", rep["risk_type"])
                col3.metric("Vezes Reportado", rep["report_count"])
                col4.metric("Último Report", rep["last_seen"][:10] if rep["last_seen"] else "—")
                st.caption(f"Primeiro registo: {rep['first_seen']}")

                if data["messages"]:
                    st.subheader("📨 Mensagens Anteriores")
                    for msg in data["messages"]:
                        with st.expander(f"[{msg['date']}] {msg['risk_level']} — {msg['risk_type']}"):
                            st.write(msg["message"])
                            st.caption(f"Pontuação: {msg['score']}")
        else:
            st.warning("Por favor, introduz um número.")

    st.divider()
    st.subheader("📵 Números Mais Reportados")
    top = get_top_suspicious_numbers(10)
    if top:
        df_top = pd.DataFrame(top)
        df_top.columns = ["Número", "Tipo de Fraude", "Nível de Risco", "Reports", "Último Report"]
        st.dataframe(df_top, use_container_width=True)
    else:
        st.info("Ainda não há números registados.")

    st.divider()
    st.subheader("🚫 Blacklist Manual")
    col_add, col_list = st.columns(2)

    with col_add:
        st.markdown("**Adicionar número à blacklist**")
        bl_number = st.text_input("Número", placeholder="+258 84 000 0000", key="bl_num")
        bl_reason = st.text_input("Motivo", placeholder="Ex: Confirmado fraude MPesa", key="bl_reas")
        if st.button("🚫 Adicionar"):
            if bl_number.strip():
                add_to_blacklist(bl_number.strip(), bl_reason)
                st.success(f"Número {bl_number} adicionado!")
            else:
                st.warning("Introduz um número.")

    with col_list:
        st.markdown("**Números na blacklist**")
        blacklist = get_blacklist()
        if blacklist:
            for entry in blacklist:
                with st.expander(f"🚫 {entry['phone_number']}"):
                    st.write(f"Motivo: {entry['reason'] or 'Não especificado'}")
                    st.caption(f"Adicionado em: {entry['date_added']}")
                    if st.button("🗑️ Remover", key=f"rm_{entry['phone_number']}"):
                        remove_from_blacklist(entry["phone_number"])
                        st.rerun()
        else:
            st.info("Blacklist vazia.")


# ============================================================
# PÁGINA 3: Dashboard Estatístico
# ============================================================
elif page == "📊 Dashboard Estatístico":
    st.title("📊 Dashboard Estatístico")

    conn = get_connection()
    df = pd.read_sql("SELECT * FROM logs", conn)
    conn.close()

    if df.empty:
        st.info("Ainda não há análises registadas.")
    else:
        df["date"] = pd.to_datetime(df["date"])

        st.subheader("🔍 Filtros")
        f1, f2, f3 = st.columns(3)

        with f1:
            risk_filter = st.multiselect(
                "Nível de Risco",
                options=["Alto", "Médio", "Baixo", "Nenhum"],
                default=["Alto", "Médio", "Baixo", "Nenhum"]
            )
        with f2:
            type_filter = st.multiselect(
                "Tipo de Risco",
                options=df["risk_type"].unique().tolist(),
                default=df["risk_type"].unique().tolist()
            )
        with f3:
            min_date = df["date"].min().date()
            max_date = df["date"].max().date()
            date_range = st.date_input("Período", value=(min_date, max_date))

        df_filtered = df[
            (df["risk_level"].isin(risk_filter)) &
            (df["risk_type"].isin(type_filter))
        ]
        if len(date_range) == 2:
            df_filtered = df_filtered[
                (df_filtered["date"].dt.date >= date_range[0]) &
                (df_filtered["date"].dt.date <= date_range[1])
            ]

        st.divider()

        feedback_stats = get_feedback_stats()
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total de Análises", len(df_filtered))
        c2.metric("Alto Risco", len(df_filtered[df_filtered["risk_level"] == "Alto"]))
        c3.metric("Média de Pontuação", f"{df_filtered['score'].mean():.1f}")
        c4.metric("Precisão (feedback)", f"{feedback_stats['accuracy']}%",
                  help=f"{feedback_stats['correct']} correctas / {feedback_stats['total']} avaliadas")

        st.divider()

        st.subheader("📈 Evolução Temporal de Análises")
        df_time = df_filtered.copy()
        df_time["dia"] = df_time["date"].dt.date
        df_time_grouped = df_time.groupby(["dia", "risk_level"]).size().reset_index(name="count")
        if not df_time_grouped.empty:
            fig_time = px.line(
                df_time_grouped, x="dia", y="count", color="risk_level",
                markers=True,
                color_discrete_map={"Alto": "#e74c3c", "Médio": "#f39c12", "Baixo": "#3498db", "Nenhum": "#2ecc71"},
                labels={"dia": "Data", "count": "Nº de Análises", "risk_level": "Nível"},
            )
            st.plotly_chart(fig_time, use_container_width=True)

        col_g1, col_g2 = st.columns(2)

        with col_g1:
            st.subheader("📊 Distribuição por Nível de Risco")
            fig1 = px.histogram(
                df_filtered, x="risk_level", color="risk_level", text_auto=True,
                color_discrete_sequence=px.colors.qualitative.Bold,
                category_orders={"risk_level": ["Nenhum", "Baixo", "Médio", "Alto"]},
            )
            st.plotly_chart(fig1, use_container_width=True)

        with col_g2:
            st.subheader("📊 Distribuição por Tipo de Risco")
            fig2 = px.histogram(
                df_filtered, x="risk_type", color="risk_type", text_auto=True,
                color_discrete_sequence=px.colors.qualitative.Prism,
            )
            st.plotly_chart(fig2, use_container_width=True)

        st.subheader("📌 Mensagens Registadas")
        df_sorted = df_filtered.sort_values("date", ascending=False)
        st.dataframe(
            df_sorted[["date", "message", "risk_level", "risk_type", "score", "reasons", "phone_number"]],
            use_container_width=True,
        )

        csv = df_sorted.to_csv(index=False).encode("utf-8")
        st.download_button(
            label="⬇️ Exportar dados como CSV",
            data=csv,
            file_name=f"analises_{datetime.now().strftime('%Y%m%d')}.csv",
            mime="text/csv",
        )