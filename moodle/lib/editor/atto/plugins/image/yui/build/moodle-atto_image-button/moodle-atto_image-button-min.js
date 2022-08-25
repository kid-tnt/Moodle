YUI.add("moodle-atto_image-button",function(c,e){var m={RESPONSIVE:"img-responsive",INPUTALIGNMENT:"atto_image_alignment",INPUTALT:"atto_image_altentry",INPUTHEIGHT:"atto_image_heightentry",INPUTSUBMIT:"atto_image_urlentrysubmit",INPUTURL:"atto_image_urlentry",INPUTSIZE:"atto_image_size",INPUTWIDTH:"atto_image_widthentry",IMAGEALTWARNING:"atto_image_altwarning",IMAGEBROWSER:"openimagebrowser",IMAGEPRESENTATION:"atto_image_presentation",INPUTCONSTRAIN:"atto_image_constrain",INPUTCUSTOMSTYLE:"atto_image_customstyle",IMAGEPREVIEW:"atto_image_preview",IMAGEPREVIEWBOX:"atto_image_preview_box",ALIGNSETTINGS:"atto_image_button"},t={INPUTURL:"."+m.INPUTURL},a=[{name:"verticalAlign",str:"alignment_top",value:"text-top",margin:"0 0.5em"},{name:"verticalAlign",str:"alignment_middle",value:"middle",margin:"0 0.5em"},{name:"verticalAlign",str:"alignment_bottom",value:"text-bottom",margin:"0 0.5em",isDefault:!0},{name:"float",str:"alignment_left",value:"left",margin:"0 0.5em 0 0"},{name:"float",str:"alignment_right",value:"right",margin:"0 0 0 0.5em"}],u=/\d+%/,d="atto_image",I='<img src="{{url}}" alt="{{alt}}" {{#if width}}width="{{width}}" {{/if}}{{#if height}}height="{{height}}" {{/if}}{{#if presentation}}role="presentation" {{/if}}{{#if customstyle}}style="{{customstyle}}" {{/if}}{{#if classlist}}class="{{classlist}}" {{/if}}{{#if id}}id="{{id}}" {{/if}}/>';c.namespace("M.atto_image").Button=c.Base.create("button",c.M.editor_atto.EditorPlugin,[],{_currentSelection:null,_selectedImage:null,_form:null,_rawImageDimensions:null,initializer:function(){this.addButton({icon:"e/insert_edit_image",callback:this._displayDialogue,tags:"img",tagMatchRequiresAll:!1}),this.editor.delegate("dblclick",this._displayDialogue,"img",this),this.editor.delegate("click",this._handleClick,"img",this),this.editor.on("paste",this._handlePaste,this),this.editor.on("drop",this._handleDragDrop,this),this.editor.on("dragover",function(e){e.preventDefault()},this),this.editor.on("dragenter",function(e){e.preventDefault()},this)},_handleDragDrop:function(e){return!e._event||!e._event.dataTransfer||this._handlePasteOrDropHelper(e,e._event.dataTransfer)},_handlePaste:function(e){return!e._event||!e._event.clipboardData||this._handlePasteOrDropHelper(e,e._event.clipboardData)},_handlePasteOrDropHelper:function(e,t){for(var i,n=t.items,s=!1,a=0;a<n.length;a++)"file"===(i=n[a]).kind&&this._isImage(i.type)&&(this._uploadImage(i.getAsFile()),s=!0);return!s||(e.preventDefault(),e.stopPropagation(),!1)},_isImage:function(e){return 0===e.indexOf("image/")},_uploadImage:function(e){var t,i,n,s,a,o,l,r=this,h=this.get("host"),g=c.Handlebars.compile(I);for(h.saveSelection(),require(["core_form/events"],function(e){e.triggerUploadStarted(r.editor.get("id"))}),a=(t=h.get("filepickeroptions").image).savepath===undefined?"/":t.savepath,i=new FormData,s=new XMLHttpRequest,o=Object.keys(t.repositories),i.append("repo_upload_file",e),i.append("itemid",t.itemid),l=0;l<o.length;l++)if("upload"===t.repositories[o[l]].type){i.append("repo_id",t.repositories[o[l]].id);break}i.append("env",t.env),i.append("sesskey",M.cfg.sesskey),i.append("client_id",t.client_id),i.append("savepath",a),i.append("ctx_id",t.context.id),e=(new Date).getTime(),n="moodleimage_"+Math.round(1e5*Math.random())+"-"+e,h.focus(),h.restoreSelection(),a=g({url:M.util.image_url("i/loading_small","moodle"),alt:M.util.get_string("uploading",d),id:n}),h.insertContentAtFocusPoint(a),r.markUpdated(),s.onreadystatechange=function(){var e,t,i=r.editor.one("#"+n);if(4===s.readyState){if(200===s.status){if(e=JSON.parse(s.responseText)){if(e.error)throw i&&i.remove(!0),require(["core_form/events"],function(e){e.triggerUploadCompleted(r.editor.get("id"))}),new M.core.ajaxException(e);(t=e).event&&"fileexists"===e.event&&(t=e.newfile),e=g({url:t.url,presentation:!0}),t=c.Node.create(e),i?i.replace(t):r.editor.appendChild(t),r.markUpdated()}}else c.use("moodle-core-notification-alert",function(){require(["core_form/events"],function(e){e.triggerUploadCompleted(r.editor.get("id"))}),new M.core.alert({message:M.util.get_string("servererror","moodle")})}),i&&i.remove(!0);require(["core_form/events"],function(e){e.triggerUploadCompleted(r.editor.get("id"))})}},s.open("POST",M.cfg.wwwroot+"/repository/repository_ajax.php?action=upload",!0),s.send(i)},_handleClick:function(e){e=e.target,e=this.get("host").getSelectionFromNode(e);this.get("host").getSelection()!==e&&this.get("host").setSelection(e)},_displayDialogue:function(){var e;this._currentSelection=this.get("host").getSelection(),!1!==this._currentSelection&&(this._rawImageDimensions=null,(e=this.getDialogue({headerContent:M.util.get_string("imageproperties",d),width:"auto",focusAfterHide:!0,focusOnShowSelector:t.INPUTURL})).get("boundingBox").setStyle("maxWidth","90%"),e.set("bodyContent",this._getDialogueContent()).show())},_loadPreviewImage:function(e){var t=new Image,n=this;t.onerror=function(){n._form.one("."+m.IMAGEPREVIEW).setStyles({display:"none"}),n.getDialogue().centerDialogue()},t.onload=function(){var e,t,i;n._rawImageDimensions={width:this.width,height:this.height},""===(t=(e=n._form.one("."+m.INPUTWIDTH)).get("value"))&&(e.set("value",this.width),t=""+this.width),""===(i=(e=n._form.one("."+m.INPUTHEIGHT)).get("value"))&&(e.set("value",this.height),i=""+this.height),(e=n._form.one("."+m.IMAGEPREVIEW)).setAttribute("src",this.src),e.setStyles({display:"inline"}),e=n._form.one("."+m.INPUTCONSTRAIN),t.match(u)&&i.match(u)?e.set("checked",t===i):(0===this.width&&(this.width=1),0===this.height&&(this.height=1),t=Math.round(1e3*parseInt(t,10)/this.width),i=Math.round(1e3*parseInt(i,10)/this.height),e.set("checked",t===i)),n._autoAdjustSize(n),n.getDialogue().centerDialogue()},t.src=e},_getDialogueContent:function(){var e=c.Handlebars.compile(
'<form class="atto_form">{{#if showFilepicker}}<div class="mb-1"><label for="{{elementid}}_{{CSS.INPUTURL}}">{{get_string "enterurl" component}}</label><div class="input-group input-append w-100"><input class="form-control {{CSS.INPUTURL}}" type="url" id="{{elementid}}_{{CSS.INPUTURL}}" size="32"/><span class="input-group-append"><button class="btn btn-secondary {{CSS.IMAGEBROWSER}}" type="button">{{get_string "browserepositories" component}}</button></span></div></div>{{else}}<div class="mb-1"><label for="{{elementid}}_{{CSS.INPUTURL}}">{{get_string "enterurl" component}}</label><input class="form-control fullwidth {{CSS.INPUTURL}}" type="url" id="{{elementid}}_{{CSS.INPUTURL}}" size="32"/></div>{{/if}}<div style="display:none" role="alert" class="alert alert-warning mb-1 {{CSS.IMAGEALTWARNING}}">{{get_string "presentationoraltrequired" component}}</div><div class="mb-1"><label for="{{elementid}}_{{CSS.INPUTALT}}">{{get_string "enteralt" component}}</label><textarea class="form-control fullwidth {{CSS.INPUTALT}}" id="{{elementid}}_{{CSS.INPUTALT}}" maxlength="125"></textarea><div id="the-count" class="d-flex justify-content-end small"><span id="currentcount">0</span><span id="maximumcount"> / 125</span></div><div class="form-check"><input type="checkbox" class="form-check-input {{CSS.IMAGEPRESENTATION}}" id="{{elementid}}_{{CSS.IMAGEPRESENTATION}}"/><label class="form-check-label" for="{{elementid}}_{{CSS.IMAGEPRESENTATION}}">{{get_string "presentation" component}}</label></div></div><div class="mb-1"><label class="" for="{{elementid}}_{{CSS.INPUTSIZE}}">{{get_string "size" component}}</label><div id="{{elementid}}_{{CSS.INPUTSIZE}}" class="form-inline {{CSS.INPUTSIZE}}"><label class="accesshide" for="{{elementid}}_{{CSS.INPUTWIDTH}}">{{get_string "width" component}}</label><input type="text" class="form-control mr-1 input-mini {{CSS.INPUTWIDTH}}" id="{{elementid}}_{{CSS.INPUTWIDTH}}" size="4"/> x<label class="accesshide" for="{{elementid}}_{{CSS.INPUTHEIGHT}}">{{get_string "height" component}}</label><input type="text" class="form-control ml-1 input-mini {{CSS.INPUTHEIGHT}}" id="{{elementid}}_{{CSS.INPUTHEIGHT}}" size="4"/><div class="form-check ml-2"><input type="checkbox" class="form-check-input {{CSS.INPUTCONSTRAIN}}" id="{{elementid}}_{{CSS.INPUTCONSTRAIN}}"/><label class="form-check-label" for="{{elementid}}_{{CSS.INPUTCONSTRAIN}}">{{get_string "constrain" component}}</label></div></div></div><div class="form-inline mb-1"><label class="for="{{elementid}}_{{CSS.INPUTALIGNMENT}}">{{get_string "alignment" component}}</label><select class="custom-select {{CSS.INPUTALIGNMENT}}" id="{{elementid}}_{{CSS.INPUTALIGNMENT}}">{{#each alignments}}<option value="{{value}}">{{get_string str ../component}}</option>{{/each}}</select></div><input type="hidden" class="{{CSS.INPUTCUSTOMSTYLE}}"/><br/><div class="mdl-align"><div class="{{CSS.IMAGEPREVIEWBOX}}"><img class="{{CSS.IMAGEPREVIEW}}" alt="" style="display: none;"/></div><button class="btn btn-secondary {{CSS.INPUTSUBMIT}}" type="submit">{{get_string "saveimage" component}}</button></div></form>'),t=this.get("host").canShowFilepicker("image"),e=c.Node.create(e({elementid:this.get("host").get("elementid"),CSS:m,component:d,showFilepicker:t,alignments:a}));return this._form=e,this._applyImageProperties(this._form),this._form.one("."+m.INPUTURL).on("blur",this._urlChanged,this),this._form.one("."+m.IMAGEPRESENTATION).on("change",this._updateWarning,this),this._form.one("."+m.INPUTALT).on("change",this._updateWarning,this),this._form.one("."+m.INPUTWIDTH).on("blur",this._autoAdjustSize,this),this._form.one("."+m.INPUTHEIGHT).on("blur",this._autoAdjustSize,this,!0),this._form.one("."+m.INPUTCONSTRAIN).on("change",function(e){e.target.get("checked")&&this._autoAdjustSize(e)},this),this._form.one("."+m.INPUTURL).on("blur",this._urlChanged,this),this._form.one("."+m.INPUTSUBMIT).on("click",this._setImage,this),t&&this._form.one("."+m.IMAGEBROWSER).on("click",function(){this.get("host").showFilepicker("image",this._filepickerCallback,this)},this),this._form.one("."+m.INPUTALT).on("keyup",this._handleKeyup,this),e},_autoAdjustSize:function(g,e){var t,i,n,d,s,a,o,l,r,h;e=e||!1,t=this._form.one("."+m.INPUTWIDTH),i="width",n=this._form.one("."+m.INPUTHEIGHT),d="height",h=this._form.one("."+m.INPUTCONSTRAIN),s=t.get("value"),a=n.get("value"),o=this._form.one("."+m.IMAGEPREVIEW),this._rawImageDimensions&&(""===s&&(s=this._rawImageDimensions[i],t.set("value",s),s=t.get("value")),o.setStyles({width:null,height:null}),h.get("checked")?(e&&(h=t,t=n,n=h,h=i,i=d,d=h,h=s,s=a,a=h),s.match(u)?(a=s,l=parseInt(s,10),r=this._rawImageDimensions.width/100*l,o.setStyle("width",r),r=this._rawImageDimensions.height/100*l,o.setStyle("height",r)):(a=Math.round(s/this._rawImageDimensions[i]*this._rawImageDimensions[d]),e?o.setStyles({width:a,height:s}):o.setStyles({width:s,height:a})),n.set("value",a)):(s.match(u)?(l=parseInt(s,10),r=this._rawImageDimensions.width/100*l,o.setStyle("width",r+"px")):o.setStyle("width",s+"px"),a.match(u)?(l=parseInt(a,10),r=this._rawImageDimensions.height/100*l,o.setStyle("height",r+"px")):o.setStyle("height",a+"px")))},_filepickerCallback:function(e){""!==e.url&&(this._form.one("."+m.INPUTURL).set("value",e.url),this._form.one("."+m.INPUTWIDTH).set("value",""),this._form.one("."+m.INPUTHEIGHT).set("value",""),this._loadPreviewImage(e.url))},_applyImageProperties:function(t){var e=this._getSelectedImageProperties(),i=t.one("."+m.IMAGEPREVIEW);if(!1===e)return i.setStyle("display","none"),void a.some(function(e){return!!e.isDefault&&(t.one("."+m.INPUTALIGNMENT).set("value",e.value),!0)},this);e.align&&t.one("."+m.INPUTALIGNMENT).set("value",e.align),e.customstyle&&t.one("."+m.INPUTCUSTOMSTYLE).set("value",e.customstyle),e.width&&t.one("."+m.INPUTWIDTH).set("value",e.width),e.height&&t.one("."+m.INPUTHEIGHT).set("value",e.height),e.alt&&t.one("."+m.INPUTALT).set("value",e.alt),e.src&&(t.one("."+m.INPUTURL).set("value",e.src),this._loadPreviewImage(
e.src)),e.presentation&&t.one("."+m.IMAGEPRESENTATION).set("checked","checked"),this._autoAdjustSize()},_getSelectedImageProperties:function(){var e,t,i={src:null,alt:null,width:null,height:null,align:"",presentation:!1},n=this.get("host").getSelectedNodes();return(n=n&&n.filter("img"))&&n.size()?(n=this._removeLegacyAlignment(n.item(0)),t=(this._selectedImage=n).getAttribute("style"),i.customstyle=t,(t=n.getAttribute("width")).match(u)||(t=parseInt(t,10)),(e=n.getAttribute("height")).match(u)||(e=parseInt(e,10)),0!==t&&(i.width=t),0!==e&&(i.height=e),this._getAlignmentPropeties(n,i),i.src=n.getAttribute("src"),i.alt=n.getAttribute("alt")||"",i.presentation="presentation"===n.get("role"),i):(this._selectedImage=null,!1)},_getAlignmentPropeties:function(i,n){var s;!a.some(function(e){var t=this._getAlignmentClass(e.value);return i.hasClass(t)?(n.align=e.value,!0):(e.isDefault&&(s=e.value),!1)},this)&&s&&(n.align=s)},_urlChanged:function(){var e=this._form.one("."+m.INPUTURL);""!==e.get("value")&&this._loadPreviewImage(e.get("value"))},_setImage:function(e){var t=this._form,i=t.one("."+m.INPUTURL).get("value"),n=t.one("."+m.INPUTALT).get("value"),s=t.one("."+m.INPUTWIDTH).get("value"),a=t.one("."+m.INPUTHEIGHT).get("value"),o=this._getAlignmentClass(t.one("."+m.INPUTALIGNMENT).get("value")),l=t.one("."+m.IMAGEPRESENTATION).get("checked"),g=t.one("."+m.INPUTCONSTRAIN).get("checked"),d=t.one("."+m.INPUTCUSTOMSTYLE).get("value"),r=[],h=this.get("host");if(e.preventDefault(),!this._updateWarning()){if(h.focus(),""!==i){if(this._selectedImage?h.setSelection(h.getSelectionFromNode(this._selectedImage)):h.setSelection(this._currentSelection),g&&r.push(m.RESPONSIVE),r.push(o),!s.match(u)&&isNaN(parseInt(s,10)))return void t.one("."+m.INPUTWIDTH).focus();if(!a.match(u)&&isNaN(parseInt(a,10)))return void t.one("."+m.INPUTHEIGHT).focus();e=c.Handlebars.compile(I)({url:i,alt:n,width:s,height:a,presentation:l,customstyle:d,classlist:r.join(" ")}),this.get("host").insertContentAtFocusPoint(e),this.markUpdated()}this.getDialogue({focusAfterHide:null}).hide()}},_removeLegacyAlignment:function(i){return i.getStyle("margin")&&a.some(function(e){if(i.getStyle(e.name)!==e.value)return!1;var t=c.Node.create("<div>");return t.setStyle("margin",e.margin),i.getStyle("margin")===t.getStyle("margin")&&(i.addClass(this._getAlignmentClass(e.value)),i.setStyle(e.name,null),i.setStyle("margin",null),!0)},this),i},_getAlignmentClass:function(e){return m.ALIGNSETTINGS+"_"+e},_updateWarning:function(){var e=this._form,t=!0,i=e.one("."+m.INPUTALT).get("value"),n=e.one("."+m.IMAGEPRESENTATION).get("checked"),t=""!==i||n?(e.one("."+m.IMAGEALTWARNING).setStyle("display","none"),e.one("."+m.INPUTALT).setAttribute("aria-invalid",!1),e.one("."+m.IMAGEPRESENTATION).setAttribute("aria-invalid",!1),!1):(e.one("."+m.IMAGEALTWARNING).setStyle("display","block"),e.one("."+m.INPUTALT).setAttribute("aria-invalid",!0),e.one("."+m.IMAGEPRESENTATION).setAttribute("aria-invalid",!0),!0);return this.getDialogue().centerDialogue(),t},_handleKeyup:function(){var e=this._form,t=e.one("."+m.INPUTALT).get("value").length;e.one("#currentcount").setHTML(t)}})},"@VERSION@",{requires:["moodle-editor_atto-plugin"]});