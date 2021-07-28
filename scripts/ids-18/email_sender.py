from nylas import APIClient

nylas = APIClient(
    CLIENT_ID,
    CLIENT_SECRET,
    ACCESS_TOKEN,
)

draft = nylas.drafts.create()
draft.subject = "With Love, from Nylas"
draft.body = "This email was sent using the Nylas Email API. Visit https://nylas.com for details."
# to, bcc, and cc are set with an array of email objects
# Email objects contain an email value and optional name
draft.to = [{'name': 'My Nylas Friend', 'email': 'swag@nylas.com'}]

draft.send()