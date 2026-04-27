"""
app.py
Interface Streamlit — Monitor de Phishing & Fake News
"""

import streamlit as st
import requests
from analyzer import analyze_message
from database import (
    get_connection, lookup_phone, get_top_suspicious_numbers,
    save_feedback, add_to_blacklist, remove_from_blacklist,
    get_blacklist, get_feedback_stats, is_blacklisted, get_training_data
)
from ml_model import train_models, get_model_status, should_auto_train
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

# ============================================================
# INICIALIZAÇÃO DE SESSION STATE
# ============================================================
if "is_admin" not in st.session_state:
    st.session_state["is_admin"] = False
if "page_override" not in st.session_state:
    st.session_state["page_override"] = None
if "analysis_done" not in st.session_state:
    st.session_state["analysis_done"] = False
if "last_result" not in st.session_state:
    st.session_state["last_result"] = None
if "last_text" not in st.session_state:
    st.session_state["last_text"] = ""
if "last_phone" not in st.session_state:
    st.session_state["last_phone"] = ""
if "detected_phone" not in st.session_state:
    st.session_state["detected_phone"] = ""

# ============================================================
# SIDEBAR
# ============================================================
if not os.getenv("GOOGLE_SAFE_BROWSING_API_KEY"):
    st.sidebar.warning(
        "⚠️ API Key do Google Safe Browsing não configurada.\n\n"
        "Cria um ficheiro `.env` com `GOOGLE_SAFE_BROWSING_API_KEY=a_tua_chave`."
    )

# Navegação principal
nav_options = ["📄 Analisar Mensagem", "🔎 Pesquisar Número", "📊 Dashboard Estatístico"]
selected_nav = st.sidebar.selectbox("Navegação", nav_options)

# Acesso admin escondido
with st.sidebar.expander("🔒 Acesso Admin"):
    admin_input = st.text_input("Senha", type="password", key="admin_pw")
    ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")

    if admin_input and admin_input != ADMIN_PASSWORD:
        st.error("Senha incorrecta.")

    if admin_input == ADMIN_PASSWORD and admin_input != "":
        st.session_state["is_admin"] = True
        st.success("✅ Acesso admin activo")
        if st.button("🤖 Ir para Modelos ML"):
            st.session_state["page_override"] = "🤖 Modelos ML"
            st.rerun()

# Determinar página activa:
# O override só é limpo quando o utilizador muda o selectbox manualmente
# enquanto já está fora da página ML (ou seja, saiu voluntariamente).
if st.session_state.get("page_override") == "🤖 Modelos ML" and st.session_state.get("is_admin"):
    page = "🤖 Modelos ML"
else:
    # Limpa override e admin apenas quando muda para "Analisar Mensagem" sem override activo
    if selected_nav == "📄 Analisar Mensagem" and not st.session_state.get("page_override"):
        st.session_state["is_admin"] = False
    st.session_state["page_override"] = None
    page = selected_nav


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

    # Se acabou de ser feita uma análise, mostra os resultados e um botão para nova análise
    if st.session_state["analysis_done"] and st.session_state["last_result"] is not None:
        result = st.session_state["last_result"]
        final_text = st.session_state["last_text"]
        phone_number = st.session_state["last_phone"]

        # Botão para limpar e fazer nova análise
        if st.button("🔄 Nova Análise", type="primary"):
            st.session_state["analysis_done"] = False
            st.session_state["last_result"] = None
            st.session_state["last_text"] = ""
            st.session_state["last_phone"] = ""
            st.session_state["detected_phone"] = ""
            st.session_state["phone_input"] = ""
            st.rerun()

        st.divider()

        # --- Mostra resultados ---
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
                if not isinstance(link_data, dict):
                    st.warning(f"🟡 {link} → {link_data}")
                    continue

                status = link_data.get("status", "Desconhecido")
                threat = link_data.get("threat_type", "")
                is_wa = link_data.get("whatsapp_phishing", False)
                is_trusted = link_data.get("is_trusted", False)
                h_level = link_data.get("heuristic_level", "")
                h_reasons = link_data.get("heuristic_reasons", [])
                h_score = link_data.get("heuristic_score", 0)

                # Mostrar card do link com detalhe completo
                if status == "Perigoso":
                    st.error(f"🔴 **PERIGOSO — confirmado pelo Google Safe Browsing**\n\n`{link}`\n\n⚠️ Tipo de ameaça: `{threat}`")

                elif is_wa:
                    st.error(f"🟠 **SUSPEITO — WhatsApp Phishing**\n\n`{link}`\n\nEste link é usado para roubar dados via WhatsApp. Nunca cliques!")

                elif is_trusted:
                    st.success(f"🟢 **Domínio confiável** — `{link}`")

                elif "Alto Risco" in status:
                    with st.expander(f"🔴 **Alto Risco** — `{link[:60]}{'...' if len(link)>60 else ''}`", expanded=True):
                        st.error(f"**Nível heurístico:** {h_level} (pontuação: {h_score})")
                        st.markdown("**Motivos detectados pela análise heurística:**")
                        for reason in h_reasons:
                            st.write(f"  ⚠️ {reason}")
                        st.caption("ℹ️ Este link não foi confirmado pela API do Google, mas apresenta múltiplos sinais de risco. Não cliques.")

                elif "Médio Risco" in status:
                    with st.expander(f"🟠 **Médio Risco** — `{link[:60]}{'...' if len(link)>60 else ''}`"):
                        st.warning(f"**Nível heurístico:** {h_level} (pontuação: {h_score})")
                        if h_reasons:
                            st.markdown("**Sinais detectados:**")
                            for reason in h_reasons:
                                st.write(f"  ⚠️ {reason}")
                        st.caption("ℹ️ Procede com cautela. Verifica a fonte antes de clicar.")

                elif "Baixo Risco" in status:
                    with st.expander(f"🟡 **Baixo Risco** — `{link[:60]}{'...' if len(link)>60 else ''}`"):
                        st.info(f"**Nível heurístico:** {h_level} (pontuação: {h_score})")
                        if h_reasons:
                            for reason in h_reasons:
                                st.write(f"  ℹ️ {reason}")

                else:
                    st.success(f"🟢 **Aparentemente seguro** — `{link[:60]}{'...' if len(link)>60 else ''}`")
                    if h_reasons:
                        with st.expander("Ver detalhes"):
                            for reason in h_reasons:
                                st.write(f"  ℹ️ {reason}")

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
                st.error(f"🚫 O número **{phone_number}** está na blacklist de números perigosos.")
                st.caption("Para remover da blacklist, contacte o administrador do sistema.")
            else:
                if st.button("🚫 Adicionar número à blacklist"):
                    reason = st.text_input("Motivo (opcional)", key="bl_reason")
                    add_to_blacklist(phone_number.strip(), reason)
                    st.success(f"Número {phone_number} adicionado à blacklist!")

    else:
        # --- Formulário de análise (campo limpo) ---
        tab1, tab2 = st.tabs(["✍️ Texto", "🖼️ Imagem (OCR)"])

        with tab1:
            text = st.text_area(
                "Cole aqui a mensagem suspeita...",
                placeholder="Ex: URGENTE! Clique agora no link bit.ly/xxxxx e confirme os seus dados!",
                height=180,
                key="msg_input",
            )

        with tab2:
            uploaded = st.file_uploader("Carrega uma imagem com a mensagem suspeita", type=["png", "jpg", "jpeg"])
            text_from_image = ""
            extracted_phone_from_image = ""
            if uploaded:
                try:
                    from PIL import Image, ImageEnhance
                    import numpy as np
                    import pytesseract
                    import re as _re
                    import base64
                    import json as _json

                    image = Image.open(uploaded)
                    st.image(image, caption="Imagem carregada", width=400)

                    anthropic_key = os.getenv("ANTHROPIC_API_KEY", "")

                    # ------------------------------------------------
                    # MÉTODO 1: Claude Vision API (se disponível)
                    # ------------------------------------------------
                    if anthropic_key:
                        with st.spinner("🧠 A extrair texto com IA..."):
                            try:
                                uploaded.seek(0)
                                img_bytes = uploaded.read()
                                img_b64 = base64.b64encode(img_bytes).decode()
                                ext = uploaded.name.split(".")[-1].lower()
                                mime = "image/jpeg" if ext in ["jpg","jpeg"] else "image/png"

                                resp = requests.post(
                                    "https://api.anthropic.com/v1/messages",
                                    headers={
                                        "x-api-key": anthropic_key,
                                        "anthropic-version": "2023-06-01",
                                        "content-type": "application/json"
                                    },
                                    json={
                                        "model": "claude-sonnet-4-20250514",
                                        "max_tokens": 500,
                                        "messages": [{
                                            "role": "user",
                                            "content": [
                                                {"type": "image", "source": {"type": "base64", "media_type": mime, "data": img_b64}},
                                                {"type": "text", "text": "Esta é uma captura de ecrã do WhatsApp ou SMS. Extrai APENAS: 1) o número de telefone do remetente visível no cabeçalho, 2) o texto exacto da mensagem recebida (só o conteúdo da bolha, sem hora nem data). Responde SOMENTE em JSON válido sem markdown: {\"phone\": \"...\" , \"message\": \"...\"} . Se não encontrares um dos campos, usa string vazia."}
                                            ]
                                        }]
                                    },
                                    timeout=15
                                )

                                if resp.status_code == 200:
                                    raw = resp.json()["content"][0]["text"].strip()
                                    raw = raw.replace("```json","").replace("```","").strip()
                                    parsed = _json.loads(raw)
                                    extracted_phone_from_image = parsed.get("phone","").strip()
                                    text_from_image = parsed.get("message","").strip()
                                else:
                                    st.error(f"❌ Erro API {resp.status_code}: {resp.text[:300]}")
                            except Exception as _vision_err:
                                st.error(f"⚠️ Excepção Claude Vision: {type(_vision_err).__name__}: {_vision_err}")
                                # fallback para Tesseract

                    # ------------------------------------------------
                    # MÉTODO 2: Tesseract com detecção automática da bolha
                    # ------------------------------------------------
                    if not text_from_image:
                        w_img, h_img = image.size
                        arr_rgb = np.array(image.convert("RGB"))

                        # --- Detectar se é captura de browser ou imagem directa ---
                        # Captura de browser: fundo branco/claro nas bordas
                        # Imagem directa do WhatsApp: fundo escuro
                        border_brightness = np.mean(arr_rgb[:50, :, :])
                        is_browser_capture = border_brightness > 150

                        if is_browser_capture:
                            col_means = np.mean(arr_rgb, axis=(0, 2))
                            row_means_all = np.mean(arr_rgb, axis=(1, 2))
                            dark_cols = np.where(col_means < 130)[0]
                            dark_rows = np.where(row_means_all < 130)[0]
                            st.caption(f"🔍 Debug: browser={is_browser_capture}, brilho_borda={border_brightness:.0f}, dark_cols={len(dark_cols)}, dark_rows={len(dark_rows)}")
                            if len(dark_cols) > 10 and len(dark_rows) > 10:
                                x1 = int(dark_cols[0])
                                x2 = int(dark_cols[-1])
                                y1 = int(dark_rows[0])
                                y2 = int(dark_rows[-1])
                                phone_img = image.crop((x1, y1, x2, y2))
                                st.caption(f"📱 Telefone recortado: {phone_img.size}")
                            else:
                                phone_img = image
                                st.caption("⚠️ Telefone não detectado, usando imagem completa")
                        else:
                            phone_img = image
                            st.caption(f"🔍 Debug: imagem directa, brilho_borda={border_brightness:.0f}")

                        pw, ph = phone_img.size
                        arr_phone = np.array(phone_img.convert("RGB"))

                        # --- Extrair número do cabeçalho do telefone (top 20%) ---
                        header = phone_img.crop((0, 0, pw, int(ph * 0.20)))
                        header_arr = 255 - np.array(header.convert("RGB"))
                        header_img = Image.fromarray(header_arr.astype(np.uint8)).convert("L")
                        header_img = ImageEnhance.Contrast(header_img).enhance(3.0)
                        hw, hh = header_img.size
                        header_img = header_img.resize((hw*3, hh*3), Image.LANCZOS)
                        header_text = pytesseract.image_to_string(header_img, lang="por+eng", config="--oem 3 --psm 6")
                        if not extracted_phone_from_image:
                            pm = _re.search(r"(\+?\d[\d\s]{7,14}\d)", header_text)
                            if pm:
                                extracted_phone_from_image = pm.group(1).strip()

                        # --- Detectar bolha automaticamente por brilho ---
                        # Bolha WhatsApp dark mode: brilho médio 45-100
                        row_means = np.mean(arr_phone, axis=(1, 2))
                        in_bubble = row_means >= 45
                        changes = np.diff(in_bubble.astype(int))
                        starts = np.where(changes == 1)[0] + 1
                        ends = np.where(changes == -1)[0] + 1
                        if len(starts) == 0 and in_bubble[0]:
                            starts = np.array([0])
                        if len(ends) == 0 and in_bubble[-1]:
                            ends = np.array([ph])

                        best_start, best_end = 0, 0
                        for s, e in zip(starts, ends):
                            if e - s > best_end - best_start:
                                best_start, best_end = s, e

                        st.caption(f"🫧 Bolha detectada: y={best_start}-{best_end} de {ph}px total")

                        if best_end > best_start + 30:
                            margin = 25
                            bubble_crop = phone_img.crop((0, max(0, best_start - margin),
                                                          pw, min(ph, best_end + margin)))
                            arr_b = np.array(bubble_crop.convert("RGB"))
                            arr_inv = 255 - arr_b
                            msg_gray = Image.fromarray(arr_inv.astype(np.uint8)).convert("L")
                        else:
                            msg_crop = phone_img.crop((int(pw*0.03), int(ph*0.28),
                                                       int(pw*0.90), int(ph*0.78)))
                            pixels = np.array(msg_crop.convert("RGB"))
                            if pixels.mean() < 100:
                                pixels = 255 - pixels
                                msg_crop = Image.fromarray(pixels.astype(np.uint8))
                            msg_gray = msg_crop.convert("L")

                        msg_gray = ImageEnhance.Contrast(msg_gray).enhance(3.5)
                        msg_gray = ImageEnhance.Sharpness(msg_gray).enhance(2.0)
                        mw, mh = msg_gray.size
                        msg_gray = msg_gray.resize((mw*4, mh*4), Image.LANCZOS)

                        raw_text = pytesseract.image_to_string(msg_gray, lang="por+eng", config="--oem 3 --psm 6")

                        skip_pats = [
                            r"^\d{1,2}:\d{2}\s*(AM|PM)?$",
                            r"^(sunday|monday|tuesday|wednesday|thursday|friday|saturday|domingo|segunda|terça|quarta|quinta|sexta|sábado)",
                            r"^(january|february|march|april|may|june|july|august|september|october|november|december|janeiro|fevereiro|março|abril|maio|junho|julho|agosto|setembro|outubro|novembro|dezembro)",
                            r"^this message is from",
                            r"^beware of smishing",
                            r"^block number",
                            r"^\+?[\d\s\-]{9,}$",
                            r"^[^\w]*$",
                            r"^.{1,3}$",
                        ]
                        clean = []
                        for line in raw_text.splitlines():
                            line = line.strip()
                            if not line:
                                continue
                            if not any(_re.search(p, line, _re.IGNORECASE) for p in skip_pats):
                                clean.append(line)
                        text_from_image = "\n".join(clean).strip()

                    # ------------------------------------------------
                    # Mostrar resultados
                    # ------------------------------------------------
                    if extracted_phone_from_image:
                        st.session_state["detected_phone"] = extracted_phone_from_image
                        st.info(f"📱 Número detectado na imagem: **{extracted_phone_from_image}**")
                    else:
                        st.session_state["detected_phone"] = ""

                    if text_from_image:
                        st.success("✅ Mensagem extraída:")
                        st.code(text_from_image)
                    else:
                        st.warning("⚠️ Não foi possível extrair o texto. Cola o texto manualmente no separador Texto.")

                except ImportError:
                    st.warning("⚠️ OCR não disponível neste ambiente.")
                except Exception as e:
                    st.warning(f"⚠️ Erro ao processar imagem: {e}. Cola o texto manualmente.")

        # Pré-preenche o campo com número detectado via session_state
        if st.session_state.get("detected_phone") and "phone_input" not in st.session_state:
            st.session_state["phone_input"] = st.session_state["detected_phone"]
        elif st.session_state.get("detected_phone") and st.session_state.get("phone_input") == "":
            st.session_state["phone_input"] = st.session_state["detected_phone"]

        phone_number = st.text_input(
            "📱 Número que enviou a mensagem (opcional)",
            placeholder="Ex: +258 84 123 4567",
            help="Preenchido automaticamente se detectado na imagem.",
            key="phone_input",
        )

        if st.button("🔍 Analisar", type="primary"):
            final_text = text if text.strip() else (text_from_image if "text_from_image" in dir() else "")

            if final_text.strip():
                with st.spinner("A analisar..."):
                    result = analyze_message(final_text, phone_number=phone_number.strip() or None)

                # Guarda resultado no session_state e faz refresh (limpa o campo)
                st.session_state["analysis_done"] = True
                st.session_state["last_result"] = result
                st.session_state["last_text"] = final_text
                st.session_state["last_phone"] = phone_number
                st.rerun()
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
        st.dataframe(df_top, width="stretch")
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
                    # Remoção protegida por senha admin
                    with st.container():
                        admin_rem_pw = st.text_input(
                            "🔒 Senha admin para remover",
                            type="password",
                            key=f"rm_pw_{entry['phone_number']}"
                        )
                        ADMIN_PW = os.getenv("ADMIN_PASSWORD", "admin123")
                        if st.button("🗑️ Remover da blacklist", key=f"rm_{entry['phone_number']}"):
                            if admin_rem_pw == ADMIN_PW:
                                remove_from_blacklist(entry["phone_number"])
                                st.success("Número removido da blacklist.")
                                st.rerun()
                            else:
                                st.error("❌ Senha incorrecta. Não tem permissão para remover.")
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
            st.plotly_chart(fig_time, width="stretch")

        col_g1, col_g2 = st.columns(2)

        with col_g1:
            st.subheader("📊 Distribuição por Nível de Risco")
            fig1 = px.histogram(
                df_filtered, x="risk_level", color="risk_level", text_auto=True,
                color_discrete_sequence=px.colors.qualitative.Bold,
                category_orders={"risk_level": ["Nenhum", "Baixo", "Médio", "Alto"]},
            )
            st.plotly_chart(fig1, width="stretch")

        with col_g2:
            st.subheader("📊 Distribuição por Tipo de Risco")
            fig2 = px.histogram(
                df_filtered, x="risk_type", color="risk_type", text_auto=True,
                color_discrete_sequence=px.colors.qualitative.Prism,
            )
            st.plotly_chart(fig2, width="stretch")

        st.subheader("📌 Mensagens Registadas")
        df_sorted = df_filtered.sort_values("date", ascending=False)
        st.dataframe(
            df_sorted[["date", "message", "risk_level", "risk_type", "score", "reasons", "phone_number"]],
            width="stretch",
        )

        csv = df_sorted.to_csv(index=False).encode("utf-8")
        st.download_button(
            label="⬇️ Exportar dados como CSV",
            data=csv,
            file_name=f"analises_{datetime.now().strftime('%Y%m%d')}.csv",
            mime="text/csv",
        )


# ============================================================
# PÁGINA 4: Modelos ML (apenas admin)
# ============================================================
elif page == "🤖 Modelos ML":
    st.title("🤖 Modelos de Machine Learning")
    st.markdown("""
    O sistema aprende automaticamente com as mensagens analisadas.
    Quanto mais mensagens forem submetidas e avaliadas, mais preciso fica.
    """)

    status = get_model_status()
    st.subheader("📊 Estado dos Modelos")

    col1, col2, col3 = st.columns(3)
    with col1:
        nb_s = status["naive_bayes"]
        if nb_s["trained"]:
            st.success(f"✅ **Naive Bayes**\nTreinado: {nb_s['last_trained']}\nTamanho: {nb_s['size_kb']} KB")
        else:
            st.warning("⏳ **Naive Bayes**\nAinda não treinado")
    with col2:
        rf_s = status["random_forest"]
        if rf_s["trained"]:
            st.success(f"✅ **Random Forest**\nTreinado: {rf_s['last_trained']}\nTamanho: {rf_s['size_kb']} KB")
        else:
            st.warning("⏳ **Random Forest**\nAinda não treinado")
    with col3:
        st.info(f"🧠 **Claude (Anthropic)**\n{status['claude']['note']}")

    st.divider()

    texts, labels = get_training_data()
    st.subheader("📚 Dados de Treino Disponíveis")
    col_d1, col_d2 = st.columns(2)
    col_d1.metric("Total de amostras", len(texts))
    col_d2.metric("Mínimo necessário", status["min_samples"])

    if len(texts) > 0:
        from collections import Counter
        label_counts = Counter(labels)
        df_labels = pd.DataFrame(list(label_counts.items()), columns=["Tipo", "Quantidade"])
        fig = px.bar(df_labels, x="Tipo", y="Quantidade", color="Tipo",
                     color_discrete_sequence=px.colors.qualitative.Bold)
        st.plotly_chart(fig, width="stretch")

    st.divider()

    st.subheader("⚙️ Treino Automático")
    if len(texts) >= status["min_samples"]:
        st.success(f"✅ Dados suficientes para treinar ({len(texts)} amostras).")
        if should_auto_train(texts, labels):
            st.info("🔄 O sistema vai treinar automaticamente na próxima análise.")
    else:
        faltam = status["min_samples"] - len(texts)
        st.warning(f"⏳ Faltam **{faltam}** amostras. Continua a submeter e avaliar mensagens!")

    st.divider()

    st.subheader("🔧 Treino Manual")
    if st.button("🚀 Treinar Modelos Agora"):
        if len(texts) < status["min_samples"]:
            st.error(f"❌ Dados insuficientes. Mínimo: {status['min_samples']}. Actual: {len(texts)}")
        else:
            with st.spinner("A treinar os modelos..."):
                train_result = train_models(texts, labels)
            if train_result["success"]:
                st.success("✅ Modelos treinados com sucesso!")
                for model_name, info in train_result["models"].items():
                    if "accuracy" in info:
                        st.metric(f"{model_name.replace('_', ' ').title()} — Precisão", f"{info['accuracy']}%")
                    elif "error" in info:
                        st.error(f"Erro em {model_name}: {info['error']}")
            else:
                st.error(f"❌ Erro: {train_result['error']}")

    st.divider()

    st.subheader("🔑 Configuração Claude API")
    if os.getenv("ANTHROPIC_API_KEY"):
        st.success("✅ ANTHROPIC_API_KEY configurada — Claude disponível para classificação.")
    else:
        st.warning("⚠️ ANTHROPIC_API_KEY não configurada. Adiciona no Streamlit Cloud em Settings → Secrets:\n```\nANTHROPIC_API_KEY = 'sk-ant-...'\n```")

    st.divider()
    # Botão para sair do modo admin
    if st.button("🔓 Sair do modo Admin"):
        st.session_state["is_admin"] = False
        st.session_state["page_override"] = None
        st.rerun()