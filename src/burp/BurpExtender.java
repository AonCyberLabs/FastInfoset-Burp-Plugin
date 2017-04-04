/*
* XML Fast Infoset Burp Plugin v0.1
* (c) Krzysztof Wegrzynek, 2017
*/

package burp;

import com.sun.xml.fastinfoset.sax.SAXDocumentSerializer;
import java.awt.Component;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.List;
import java.util.zip.GZIPInputStream;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamResult;
import org.jvnet.fastinfoset.*;
import java.util.zip.GZIPOutputStream;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.transform.TransformerConfigurationException;
import org.xml.sax.SAXException;
import org.xml.sax.SAXNotRecognizedException;
import org.xml.sax.SAXNotSupportedException;

public class BurpExtender implements IBurpExtender, IMessageEditorTabFactory {

	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		this.callbacks = callbacks;
		helpers = callbacks.getHelpers();
		callbacks.setExtensionName("XML Fast Infoset");
		callbacks.registerMessageEditorTabFactory(this);
	}

	@Override
	public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
		return new FastInfoSetDecoderTab(controller, editable);
	}

	class FastInfoSetDecoderTab implements IMessageEditorTab {
		private boolean editable;
                private ITextEditor txtInput;
		private byte[] currentMessage;
		private Transformer tx;

		public FastInfoSetDecoderTab(IMessageEditorController controller, boolean editable) {
                    this.editable = editable;
                        txtInput = callbacks.createTextEditor();
                        txtInput.setEditable(editable);

                    try {
				tx = TransformerFactory.newInstance().newTransformer();
                                
			} catch (TransformerConfigurationException e) {
				throw new FastInfoSetBurpException(e);
			}

			txtInput = callbacks.createTextEditor();
			txtInput.setEditable(false);
		}

		@Override
		public String getTabCaption() {
			return "XML Fast Infoset";
		}

		@Override
		public Component getUiComponent() {
			return txtInput.getComponent();
		}

		private boolean isMatch(List<String> headers, String name, String value) {
			for (String header : headers) {
				if (header.startsWith(name)) {
					return header.contains(value);
				}
			}
			return false;
		}

		@Override
		public boolean isEnabled(byte[] content, boolean isRequest) {
			List<String> headers = null;
			if (isRequest) {
				IRequestInfo request = helpers.analyzeRequest(content);
				headers = request.getHeaders();
			} else {
				IResponseInfo response = helpers.analyzeResponse(content);
				headers = response.getHeaders();
			}
			return isMatch(headers, "Content-Type", "application/fastinfoset");
		}

		private byte[] decodeFastInfoSetStream(byte[] content) {
			try (InputStream input = new ByteArrayInputStream(content);
				ByteArrayOutputStream output = new ByteArrayOutputStream()) {
				tx.transform(new FastInfosetSource(input), new StreamResult(output));
				return output.toByteArray();
			} catch (Exception e) {
				throw new FastInfoSetBurpException(e);
			}
		}

		private byte[] unzip(byte[] content) {
			try (ByteArrayOutputStream out = new ByteArrayOutputStream();
					GZIPInputStream zipStream = new GZIPInputStream(new ByteArrayInputStream(content))) {
				byte[] buffer = new byte[1024];
				int length;
				while ((length = zipStream.read(buffer)) > 0) {
					out.write(buffer, 0, length);
				}
				return out.toByteArray();
			} catch (IOException e) {
				throw new FastInfoSetBurpException(e);
			}
		}

		private byte[] decodeMessage(byte[] content, boolean isRequest) {
			int offset = -1;
			List<String> headers = null;
			if (isRequest) {
				IRequestInfo request = helpers.analyzeRequest(content);
				offset = request.getBodyOffset();
				headers = request.getHeaders();
			} else {
				IResponseInfo response = helpers.analyzeResponse(content);
				offset = response.getBodyOffset();
				headers = response.getHeaders();
			}
                        byte[] header = Arrays.copyOfRange(content, 0, offset);
			byte[] body = Arrays.copyOfRange(content, offset, content.length);

			if (isMatch(headers, "Content-Encoding", "gzip")) {
				body = unzip(body);
			}
                        body = decodeFastInfoSetStream(body);
                        ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
                    try {
                        outputStream.write(header);
                        outputStream.write(body);
                    } catch (IOException e) {
                        throw new burp.FastInfoSetBurpException(e);
                    }                       
                        byte all[] = outputStream.toByteArray();
			return all;
		}
                
                private byte[] zip(byte[] content) {
                    GZIPOutputStream zipStream =
                            null;
                    byte[] compressedData = null;
                    try {
                        ByteArrayOutputStream byteStream =
                                new ByteArrayOutputStream(content.length);
                        zipStream = new GZIPOutputStream(byteStream);
                        zipStream.write(content);
                        zipStream.close();
                        byteStream.close();
                      
                        compressedData = byteStream.toByteArray();
                        
                    } catch (IOException e) {
                        throw new burp.FastInfoSetBurpException(e);
                    } finally {
                        try {
                            zipStream.close();
                        } catch (IOException e) {
				throw new burp.FastInfoSetBurpException(e);
			}
                    }
                return compressedData;
                }
                
                private byte[] encodeFastInfoSetStream(byte[] content) {
                    InputStream xmlDocument = new ByteArrayInputStream(content);
                    byte[] outarr = null;
                    ByteArrayOutputStream fiDocument =  new ByteArrayOutputStream();
                    SAXDocumentSerializer saxDocumentSerializer = new SAXDocumentSerializer();
                    saxDocumentSerializer.setOutputStream(fiDocument);
                    SAXParserFactory saxParserFactory = SAXParserFactory.newInstance();
                    saxParserFactory.setNamespaceAware(true);
                    SAXParser saxParser=null;
                    try {
                        saxParser = saxParserFactory.newSAXParser();
                    } catch (ParserConfigurationException e) {
                        throw new burp.FastInfoSetBurpException(e);
                    } catch (SAXException ex) {
                        throw new burp.FastInfoSetBurpException(ex);
                    }
                    try {
                        // Set the lexical handler
                        saxParser.setProperty("http://xml.org/sax/properties/lexical-handler", saxDocumentSerializer);
                    } catch (SAXNotRecognizedException ex) {
                        throw new burp.FastInfoSetBurpException(ex);
                    } catch (SAXNotSupportedException ex) {
                        throw new burp.FastInfoSetBurpException(ex);
                    }

                    try {
                        // Parse the XML document and convert to a fast infoset document
                        saxParser.parse(xmlDocument, saxDocumentSerializer);
                    
                    } catch (SAXException ex) {
                        throw new burp.FastInfoSetBurpException(ex);
                    } catch (IOException ex) {
                        throw new burp.FastInfoSetBurpException(ex);
                    }
                    try {
                        fiDocument.close();
                    } catch (IOException ex) {
                        throw new burp.FastInfoSetBurpException(ex);
                    }
                    return fiDocument.toByteArray();
		}
                
                public byte[] encodeMessage(byte[] content) {
			int offset = -1;
                        List<String> headers = null;
				IRequestInfo request = helpers.analyzeRequest(content);
                                IResponseInfo response = helpers.analyzeResponse(content);
				headers = response.getHeaders();
                                offset = response.getBodyOffset();
                        byte[] header = Arrays.copyOfRange(content, 0, offset);
                        byte[] body = Arrays.copyOfRange(content, offset, content.length);
                        body = encodeFastInfoSetStream(body);
			if (isMatch(headers, "Content-Encoding", "gzip")) {
				body=zip(body);
			}
                        ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
                        try {
                            outputStream.write(header);
                            outputStream.write(body);
                        } catch (IOException ex) {
                            throw new burp.FastInfoSetBurpException(ex);
                        }                       
                            byte all[] = outputStream.toByteArray();
                     return all;
                }

		@Override
		public void setMessage(byte[] content, boolean isRequest) {
                    if (content == null) {
				txtInput.setText(null);
                                txtInput.setEditable(false);
			} else {
				byte[] message = decodeMessage(content, isRequest);
				txtInput.setText(message);
                                txtInput.setEditable(editable);
			}
			currentMessage = content;     
		}

		@Override
		public byte[] getMessage() {
                // determine whether the user modified the deserialized data
                   if (txtInput.isTextModified())
                    {
                        // reserialize the data
                        byte[] text = txtInput.getText();
                        byte[] message = encodeMessage(text);
                        // update the request with the new parameter value
                        return message;
                    }
                    else return currentMessage;

		}

		@Override
		public boolean isModified() {
			return txtInput.isTextModified();
		}

		@Override
		public byte[] getSelectedData() {
			return txtInput.getSelectedText();
		}
	}
}
