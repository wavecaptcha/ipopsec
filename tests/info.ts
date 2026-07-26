import { getInfo } from '@wavecaptcha/ipopsec';

for (const ip of ['152.53.144.50', '8.8.8.8', '1.1.1.1']) {
    console.log(ip, await getInfo(ip));
}
