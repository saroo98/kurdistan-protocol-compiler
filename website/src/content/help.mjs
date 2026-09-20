import {link,note,table} from '../components/primitives.mjs';
const topics=[
 ['cannot-connect','My VPN will not connect','Check the reason before changing the setup.',[
 ['What happened','The intended session could not start or stay active. An animation or a saved profile is not evidence that the VPN is on.'],
 ['What has not changed','Do not assume the profile needs deleting. First inspect the state shown by the app.'],
 ['What to do next','Check that Wi-Fi or mobile data is available. Then check the profile’s validity, Android VPN permission, device unlock state and any protected-storage warning. Follow the specific reason rather than repeatedly pressing Connect.'],
 ],['profile-expired','permission','saved-setup']],
 ['profile-expired','My profile expired','Ask for a new setup rather than bypassing the date.',[
 ['What happened','The profile is outside its permitted validity period and cannot start the intended session.'],
 ['What has not changed','The local saved copy may still be present. Changing theme or Grandma Mode does not restore its validity.'],
 ['What to do next','Ask the person who operates your deployment for an appropriate newer signed profile. Preview it, compare the owner identity and confirm the replacement. Do not change the clock to work around expiry.'],
 ],['fingerprint','cannot-connect']],
 ['profile-revoked','My profile was withdrawn','The owner has withdrawn access to this deployment.',[
 ['What happened','A revoked profile must not continue as though it were valid. This is different from Android withdrawing VPN permission.'],
 ['What has not changed','Your display preferences do not change the owner’s decision. The app must not silently switch to an unauthorized path.'],
 ['What to do next','Contact the deployment owner through the channel you already trust. Use a replacement they deliberately issue, or another valid profile you have explicitly verified.'],
 ],['permission','fingerprint']],
 ['permission','My phone asks for permission','Android needs an explicit decision from you.',[
 ['What happened','Android has not granted, or has withdrawn, permission for the app to establish its VPN interface.'],
 ['What has not changed','This does not necessarily mean your owner-issued profile was revoked or lost.'],
 ['What to do next','Read the system VPN permission message and approve only the intended Kurdistan VPN app. When Android manages Always-on VPN, review the real system VPN settings. A website demo cannot grant this permission.'],
 ],['cannot-connect','phone-restarted']],
 ['phone-restarted','My phone restarted','Unlock first, then read the real connection state.',[
 ['What happened','A restarted or not-yet-unlocked phone can have different storage and system-start conditions from an app that was already running.'],
 ['What has not changed','A saved Always-on preference is not proof that a protected tunnel returned after reboot.'],
 ['What to do next','Unlock the device and reopen the app. Review its current state and any system VPN policy. Do not assume browsing is protected until the actual native session and applicable platform policy are confirmed.'],
 ],['cannot-connect','saved-setup']],
 ['fingerprint','How do I check who sent the profile?','Compare the complete code through a channel you already trust.',[
 ['What happened','You have received a profile, but signature validity alone cannot tell you that its owner is the person you intended.'],
 ['What has not changed','Nothing needs to be accepted just because the preview looks plausible.'],
 ['What to do next','Ask the intended deployment owner to show or read the full deployment fingerprint over a separately trusted channel. Compare every part. If it differs or you cannot establish the owner, stop rather than confirm trust.'],
 ],['profile-expired','profile-revoked']],
 ['saved-setup','My saved setup needs attention','Keep the information before trying a repair.',[
 ['What happened','Protected storage or key consistency could not be established. The exact reason matters.'],
 ['What has not changed','A safely stopped app should not silently delete the existing ciphertext, recreate keys or replace a profile.'],
 ['What to do next','Ask your trusted helper to read the specific recovery reason. Use a supported, explicit backup/restore or recovery procedure. Do not start with a full reset; save a safe diagnostic summary where available.'],
 ],['safe-diagnostics','cannot-connect']],
 ['safe-diagnostics','How do I share information for help?','Review the summary before you share it.',[
 ['What happened','Your helper needs enough information to understand the problem, not your passwords or browsing history.'],
 ['What has not changed','This website has no automatic support upload. A previewed summary stays with you until you deliberately share it.'],
 ['What to do next','Use the native app’s redacted diagnostic workflow where available. Check its preview. Do not send private keys, full profiles, credentials, destinations or DNS questions. Share only with the intended recipient.'],
 ],['saved-setup','cannot-connect']],
 ['local-test','The test is on, but I have no Internet','A local conformance test is not a public Internet connection.',[
 ['What happened','The local runtime can exercise an owned-loopback path without providing Internet egress.'],
 ['What has not changed','A successful local test does not transform an engineering build into a production VPN release.'],
 ['What to do next','Read the build’s declared scope. Stop the local test when finished and consult the engineering guide. Do not disable authentication or reroute traffic to claim a successful production connection.'],
 ],['cannot-connect']],
];
export const helpPages=[{
 slug:'help',title:'Kurdistan VPN help — start with what happened',heading:'Start with what happened.',description:'Plain-language help for connection problems, expired profiles, permission, restarts, fingerprint verification and safe diagnostics.',category:'Help',eyebrow:'HELP',lead:'You should not need to know a protocol name to find the next step.',social:'simple',sections:[{id:'choose',title:'Which sounds like your problem?',body:c=>`<div class="help-list">${topics.map(([id,title,lede])=>`<a href="${c.p('help/'+id)}"><span><strong>${title}</strong><small>${lede}</small></span><span aria-hidden="true">↗</span></a>`).join('')}</div>`},{id:'received',title:'Someone sent you a profile?',body:c=>`<p>Start with the guided import explanation. Do not paste real profile data into the website’s design preview.</p>${link('Read the import guide',c.p('docs/profile'))}${link('Explore Grandma Mode',c.p('simple'))}`}],related:['docs/profile','simple','trust'],sources:['readme','strings']},
 ...topics.map(([id,title,lede,sections,related])=>({slug:'help/'+id,title:title+' — Kurdistan VPN help',heading:title,description:lede+' Plain-language Kurdistan VPN help with a clear next step.',category:'Help',eyebrow:'HELP / NEXT STEP',lead:lede,social:'simple',sections:sections.map(([heading,text],i)=>({id:['happened','kept','next'][i],title:heading,body:()=>`<p class="help-answer">${text}</p>`})).concat({id:'boundary',title:'Before you continue',body:()=>note('Check the actual app and build','These instructions explain the source model. The browser preview cannot inspect, protect, unlock or repair your real phone.')}),related:related.map(x=>'help/'+x).concat('help'),sources:['readme','strings','selfhost']})),
];
