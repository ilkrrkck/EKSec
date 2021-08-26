
import shodan
from rich.console import Console
from rich.table import Table

### BURASI EKSİK. SONUÇLAR KISALTILMALI ###
SHODAN_API_KEY = "2eZtvvdkYevanYFJqHh5NVONc8DsBGgE"
api = shodan.Shodan(SHODAN_API_KEY)

def search_query(sorgu):
    try:
        # Search Shodan
        query = sorgu['sorgu']
        results = api.search(query, minify=True, limit=10, page=1)  # ..
        # filtreler shodan limited hesabı yüzünden kullanılamıyor
        # minify özet bilgi daha çok bilgi için parametre verilebilir
        # limit : resutlt limiti
        # Show the results
        # print(results)
        print('Results found: {}'.format(results['total']))
        console = Console(color_system="windows")

        for result in results['matches']:
            tablo = Table(show_header=True, header_style="bold magenta")
            try:
                #print('tags: {}'.format(result['tags']))  # ..
                tablo.add_row('tags: {}'.format(result['tags']))
            except:
                tablo.add_column(result['ip_str'])
                tablo.add_row(f"Organization: {result.get('org', 'n/a')}\n"
                              f"Location : {result['location']['country_name']},{result['location']['city']}\n"
                              f"Open Port: {result['port']}\n")
                console.print(tablo)
    except shodan.APIError as e:
        print('Error: {}'.format(e))
    return 0


# region host_Tarama


def search_host(host_IP):
    console = Console(color_system="windows")
    search_IP = host_IP['host']
    host = api.host(search_IP)  # deneme
    # print(host)
    tablo = Table(show_header=True, header_style="bold magenta")
    tablo.add_column(f"{host['ip_str']}")
    try:
        # Print general info
        tablo.add_row(f"Organization: {host.get('org', 'n/a')}\n"
                      f"City : {host['city']}\n"
                      f"Operating System: {host.get('os', 'n/a')}\n"
                      f"Vulns : {host['vulns']}\n")
    except Exception as e:
        tablo.add_row(f"Organization: {host.get('org', 'n/a')}\n"
                      f"City : {host['city']}\n"
                      f"Operating System: {host.get('os', 'n/a')}\n"
                      f"Vulns : bulunamadı!\n")
        # Print all banners
    for item in host['data']:
        tablo.add_row(f"Port : {item['port']}\n"
                      f"{item['data']}\n")
# endregion
    console.print(tablo)
