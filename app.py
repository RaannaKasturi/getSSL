import gradio as gr
from main import main

def run(i_domains, wildcard, email, ca_server, key_type, key_size=None, key_curve=None):
    pvt, pvt_file, cert, cert_file = main(i_domains, wildcard, email, ca_server, key_type, key_size, key_curve)
    return pvt, pvt_file, cert, cert_file

def update_key_options(key_type):
    if key_type == "rsa":
        return gr.update(visible=True), gr.update(visible=False)
    else:
        return gr.update(visible=False), gr.update(visible=True)

def app():
    with gr.Blocks() as webui:
        with gr.Row():
            with gr.Column():
                domains_input = gr.Textbox(label="Enter Domains", placeholder="thenayankasturi.eu.org, dash.thenayankasturi.eu.org, www.thenayankasturi.eu.org", type="text", interactive=True)
                wildcard = gr.Checkbox(label="Wildcard SSL", interactive=True, value=False)
            email_input = gr.Textbox(label="Enter your Email ID", placeholder="nayankasturi@gmail.com", type="text", interactive=True)
        with gr.Row():
            ca_server = gr.Dropdown(label="Select Certificate Authority", choices=["Let's Encrypt (Testing)","Let's Encrypt", "Buypass (Testing)", "Buypass", "ZeroSSL", "Google (Testing)","Google", "SSL.com"], interactive=True, value="Let's Encrypt (Testing)")
            key_type = gr.Radio(label="Select SSL key type", choices=["rsa", "ec"], interactive=True, value='ec')
            key_size_dropdown = gr.Dropdown(label="Select Key Size", choices=['2048', '4096'], value='4096', visible=False)  # Initially visible
            key_curve_dropdown = gr.Dropdown(label="Select Key Curve", choices=['SECP256R1', 'SECP384R1'], value='SECP384R1', visible=True)  # Initially hidden
        
        key_type.change(fn=update_key_options, inputs=key_type, outputs=[key_size_dropdown, key_curve_dropdown])
        btn = gr.Button(value="Generate SSL Certificate")
        
        with gr.Row():
            with gr.Column():
                pvt = gr.Textbox(label="Your Private Key", placeholder="Your Private Key will appear here, after successful SSL generation", type="text", interactive=False, show_copy_button=True, lines=10, max_lines=10)
                pvtfile = gr.File(label="Download your Private Key")
            with gr.Column():
                crt = gr.Textbox(label="Your SSL Certificate", placeholder="Your SSL Certificate will appear here, after successful SSL generation", type="text", interactive=False, show_copy_button=True, lines=10, max_lines=10)
                crtfile = gr.File(label="Download your SSL Certificate")
        
        btn.click(run, inputs=[domains_input, wildcard, email_input, ca_server, key_type, key_size_dropdown, key_curve_dropdown], outputs=[pvt, pvtfile, crt, crtfile])
    webui.queue(default_concurrency_limit=15).launch()

if __name__ == "__main__":
    app()